package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"github.com/terraform-registry/terraform-registry/internal/auth"
)

// Guards for issue #1015: the publish guards parse a body the handler will
// parse again, and they must not disagree with it in the caller's favour.
//
// THE DEFECT. The guard read the buffered body with encoding/json.Unmarshal and
// ABSTAINED on error, on the stated assumption that "the handler's binding
// rejects the request". gin's JSON binding decodes with a streaming
// Decoder.Decode and never checks the stream is exhausted, while Unmarshal
// requires the whole input to be one value — so one trailing byte made the
// guard abstain and the handler succeed, and the namespace authorization added
// by #555 was skipped entirely.
//
// These tests are written against the DIVERGENCE rather than against one
// payload: the table below is the set of bodies on which the two parsers
// disagreed, and every one of them must now be refused before any
// authorization decision is reached.

// divergentBodies are bodies gin's binding ACCEPTS and encoding/json.Unmarshal
// REJECTS. Each is a bypass under the old guard.
var divergentBodies = map[string]string{
	"trailing byte":       `{"namespace":"victim","name":"vpc","system":"aws"}!`,
	"trailing garbage":    `{"namespace":"victim","name":"vpc","system":"aws"}garbage`,
	"second document":     `{"namespace":"victim","name":"vpc","system":"aws"} {"namespace":"other"}`,
	"trailing NUL":        `{"namespace":"victim","name":"vpc","system":"aws"}` + "\x00",
	"trailing open brace": `{"namespace":"victim","name":"vpc","system":"aws"}{`,
}

// ordinaryBodies are bodies both parsers accept. Failing closed must not touch
// them: a trailing newline is what every shell client sends.
var ordinaryBodies = map[string]string{
	"plain":                  `{"namespace":"team","name":"vpc","system":"aws"}`,
	"trailing newline":       `{"namespace":"team","name":"vpc","system":"aws"}` + "\n",
	"trailing CRLF":          `{"namespace":"team","name":"vpc","system":"aws"}` + "\r\n",
	"leading+trailing space": "  " + `{"namespace":"team","name":"vpc","system":"aws"}` + " \t\n",
}

// TestGinAcceptsWhatUnmarshalRejects pins the PREMISE of this whole file
// against the gin version actually in go.mod.
//
// Without it the tests below could pass for the wrong reason: if a future gin
// started rejecting trailing data, "the guard refuses these bodies" would still
// hold while the divergence it defends against had quietly ceased to exist —
// and the next person to simplify the guard back to Unmarshal would find every
// test green.
//
// MUTATION: none needed; this test fails by itself the day the premise changes,
// which is the point.
func TestGinAcceptsWhatEncodingJSONRejects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, raw := range divergentBodies {
		t.Run(name, func(t *testing.T) {
			var viaUnmarshal struct {
				Namespace string `json:"namespace"`
			}
			if err := json.Unmarshal([]byte(raw), &viaUnmarshal); err == nil {
				t.Fatalf("encoding/json accepted %q, so it is not a divergent body and this table is stale", raw)
			}

			var viaGin struct {
				Namespace string `json:"namespace"`
			}
			var bindErr error
			r := gin.New()
			r.POST("/x", func(c *gin.Context) {
				bindErr = c.ShouldBindJSON(&viaGin)
				c.Status(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(raw)))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(httptest.NewRecorder(), req)

			if bindErr != nil {
				t.Skipf("gin now rejects %q too (%v): the divergence this file defends against is gone, "+
					"and the guard's fail-closed behaviour is now belt and braces", raw, bindErr)
			}
			if viaGin.Namespace != "victim" {
				t.Fatalf("gin bound namespace=%q, want victim", viaGin.Namespace)
			}
		})
	}
}

// GUARD publish-guard-refuses-a-body-it-cannot-read-as-one-value. The bypass
// itself: under the old guard each of these reached the handler with NO
// namespace authorization at all. The handler is wired to fail the test if it
// is ever reached, and no database expectation is staged, so an abstaining
// guard fails twice over.
//
// MUTATION: restore json.Unmarshal + c.Next() on error; or drop the dec.More()
// check.
func TestRequirePublishAccessFromJSON_RefusesADivergentBody(t *testing.T) {
	for name, raw := range divergentBodies {
		t.Run(name, func(t *testing.T) {
			mock, authz := newNamespaceAuthzTestDeps(t)

			reached := false
			r := gin.New()
			r.POST("/admin/modules/create",
				contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
				authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
				func(c *gin.Context) { reached = true; c.JSON(http.StatusCreated, gin.H{"ok": true}) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, jsonRequest("/admin/modules/create", raw))

			if reached {
				t.Error("the handler ran on a body the guard could not authorize: the namespace ownership " +
					"check was skipped, which is the bypass this guard exists to close")
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a refused request issued statements: %v", err)
			}
		})
	}
}

// GUARD publish-guard-still-accepts-an-ordinary-body. Failing closed is only
// safe if it refuses exactly the ambiguous bodies. A trailing newline is what
// curl sends when the body comes from a file, and refusing it would be an
// outage rather than a fix.
//
// MUTATION: refuse on any trailing byte including whitespace, e.g. by comparing
// the decoder's offset with len(raw).
func TestRequirePublishAccessFromJSON_AcceptsAnOrdinaryBody(t *testing.T) {
	for name, raw := range ordinaryBodies {
		t.Run(name, func(t *testing.T) {
			mock, authz := newNamespaceAuthzTestDeps(t)
			// An owned namespace the caller may write to: claim -> authorize.
			mock.ExpectQuery("SELECT.*FROM namespace_claims").
				WillReturnRows(sqlmock.NewRows(claimCols).AddRow("team", nsOrgA, nil, time.Now()))
			mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
				WillReturnRows(memberRow(nsOrgA, nsUserID, `["modules:write"]`))
			expectMirroredMemberRole(mock, `["modules:write"]`)

			reached := false
			r := gin.New()
			r.POST("/admin/modules/create",
				contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
				authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
				func(c *gin.Context) { reached = true; c.JSON(http.StatusCreated, gin.H{"ok": true}) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, jsonRequest("/admin/modules/create", raw))

			if !reached || w.Code != http.StatusCreated {
				t.Errorf("an ordinary body was refused: status=%d body=%s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet expectations: %v", err)
			}
		})
	}
}

// GUARD publish-guard-refuses-a-body-neither-parser-can-read. Bodies that BOTH
// parsers reject are not a bypass — the handler would 400 them too — but the
// guard must still refuse rather than abstain, because "the handler will reject
// it" is the reasoning that produced the bypass above and it is not a claim
// this guard can check. Without this case the decode-error branch is
// unexercised: every divergent body in the table above decodes cleanly and is
// caught by the trailing-data check instead, so the abort on a decode error was
// verified by nothing.
//
// MUTATION: c.Next() instead of aborting when Decode fails.
func TestRequirePublishAccessFromJSON_RefusesAnUnreadableBody(t *testing.T) {
	for name, raw := range map[string]string{
		"truncated":  `{"namespace":"victim","name":`,
		"not json":   `namespace=victim`,
		"empty body": ``,
		"array":      `["namespace","victim"]`,
	} {
		t.Run(name, func(t *testing.T) {
			mock, authz := newNamespaceAuthzTestDeps(t)
			reached := false
			r := gin.New()
			r.POST("/admin/modules/create",
				contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
				authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
				func(c *gin.Context) { reached = true; c.JSON(http.StatusCreated, gin.H{"ok": true}) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, jsonRequest("/admin/modules/create", raw))

			if reached {
				t.Error("the handler ran on a body the guard could not read at all")
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a refused request issued statements: %v", err)
			}
		})
	}
}

// GUARD publish-guard-refuses-a-body-with-no-namespace. The other half of the
// old abstain branch. It rested on the same reasoning — "the handler will
// reject it" — which is not a claim this guard can check, and which was wrong
// about the malformed case.
//
// MUTATION: restore c.Next() for an empty namespace.
func TestRequirePublishAccessFromJSON_RefusesAnAbsentNamespace(t *testing.T) {
	for name, raw := range map[string]string{
		"absent": `{"name":"vpc","system":"aws"}`,
		"empty":  `{"namespace":"","name":"vpc","system":"aws"}`,
	} {
		t.Run(name, func(t *testing.T) {
			mock, authz := newNamespaceAuthzTestDeps(t)
			reached := false
			r := gin.New()
			r.POST("/admin/modules/create",
				contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
				authz.RequirePublishAccessFromJSON(auth.ScopeModulesWrite),
				func(c *gin.Context) { reached = true; c.JSON(http.StatusCreated, gin.H{"ok": true}) })

			w := httptest.NewRecorder()
			r.ServeHTTP(w, jsonRequest("/admin/modules/create", raw))

			if reached {
				t.Error("the handler ran for a body naming no namespace, so nothing authorized where it wrote")
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a refused request issued statements: %v", err)
			}
		})
	}
}

// GUARD module-update-guard-refuses-a-divergent-body. The second, and worse,
// instance: abstaining there was read as "no namespace change requested", so a
// caller could MOVE a module they own into a namespace owned by another
// organization with the target-ownership check skipped entirely.
//
// The module lookup and its current-namespace authorization are staged, because
// they happen before the body is read; nothing after them is, so any further
// statement means the guard carried on.
//
// MUTATION: restore json.Unmarshal + c.Next() in RequireModuleUpdateAccess.
func TestRequireModuleUpdateAccess_RefusesADivergentBody(t *testing.T) {
	raw := `{"namespace":"victim"}!`

	const moduleID = "33333333-3333-3333-3333-333333333333"

	mock, authz := newNamespaceAuthzTestDeps(t)
	mock.ExpectQuery("SELECT.*FROM modules").
		WillReturnRows(sqlmock.NewRows(moduleByIDCols).AddRow(
			moduleID, nsOrgA, "mine", "vpc", "aws", nil, nil, nil, time.Now(), time.Now(), nil,
			false, nil, nil, nil,
		))
	mock.ExpectQuery("SELECT.*FROM namespace_claims").
		WillReturnRows(sqlmock.NewRows(claimCols).AddRow("mine", nsOrgA, nil, time.Now()))
	mock.ExpectQuery("SELECT.*FROM organization_members.*JOIN.*role_templates").
		WillReturnRows(memberRow(nsOrgA, nsUserID, `["modules:write"]`))
	expectMirroredMemberRole(mock, `["modules:write"]`)

	reached := false
	r := gin.New()
	r.PUT("/admin/modules/:id",
		contextSetter(withScopesAndUser([]string{string(auth.ScopeModulesWrite)}, nsUserID)),
		authz.RequireModuleUpdateAccess(auth.ScopeModulesWrite),
		func(c *gin.Context) { reached = true; c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodPut, "/admin/modules/"+moduleID, bytes.NewBufferString(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if reached {
		t.Error("the handler ran on a body the guard could not read, so a namespace move went unauthorized")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: body=%s", w.Code, w.Body.String())
	}
}
