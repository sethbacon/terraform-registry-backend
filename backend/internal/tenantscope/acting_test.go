package tenantscope

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	idtenantscope "github.com/sethbacon/terraform-suite-identity/identity/tenantscope"
)

// TestScopeIdentity_FieldParity pins this package's Scope to the shared
// module's Scope field-for-field, so a field added to either cannot be silently
// dropped by Identity: the conversion is explicit, and this is what keeps it
// honest.
func TestScopeIdentity_FieldParity(t *testing.T) {
	fields := func(tp reflect.Type) map[string]string {
		m := map[string]string{}
		for i := 0; i < tp.NumField(); i++ {
			if f := tp.Field(i); f.IsExported() {
				m[f.Name] = f.Type.String()
			}
		}
		return m
	}
	local, shared := fields(reflect.TypeOf(Scope{})), fields(reflect.TypeOf(idtenantscope.Scope{}))
	if !reflect.DeepEqual(local, shared) {
		t.Fatalf("tenantscope.Scope fields %v differ from identity/tenantscope.Scope fields %v; update Identity()", local, shared)
	}

	s := Scope{PlatformAdmin: true, OrgIDs: []string{"a", "b"}}
	want := idtenantscope.Scope{PlatformAdmin: true, OrgIDs: []string{"a", "b"}}
	if got := s.Identity(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Identity() = %+v, want %+v", got, want)
	}
}

// TestActingOrganizationHeader_IsTheWireContract pins the header name the
// frontend sends; the shared module owns it, and a rename there must be a
// coordinated change across every consumer.
func TestActingOrganizationHeader_IsTheWireContract(t *testing.T) {
	if idtenantscope.ActingOrganizationHeader != "X-Organization-Id" {
		t.Fatalf("ActingOrganizationHeader = %q, want X-Organization-Id", idtenantscope.ActingOrganizationHeader)
	}
}

func ctxWithHeader(header string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/create", nil)
	if header != "" {
		c.Request.Header.Set(idtenantscope.ActingOrganizationHeader, header)
	}
	return c
}

func TestActingOrganization(t *testing.T) {
	several := Scope{OrgIDs: []string{"a", "b"}}
	cases := []struct {
		name      string
		ctx       *gin.Context
		scope     Scope
		requested string
		want      string
		wantErr   error
	}{
		{name: "header picks among the scope", ctx: ctxWithHeader("b"), scope: several, want: "b"},
		{name: "header is trimmed", ctx: ctxWithHeader("  b \t"), scope: several, want: "b"},
		{name: "blank header falls through to the implicit rule", ctx: ctxWithHeader("   "), scope: Scope{OrgIDs: []string{"a"}}, want: "a"},
		{name: "requested wins over the header", ctx: ctxWithHeader("b"), scope: several, requested: "a", want: "a"},
		{name: "requested outside the scope is refused even with a permitted header", ctx: ctxWithHeader("b"), scope: several, requested: "zzz", wantErr: idtenantscope.ErrActingOrganizationNotPermitted},
		{name: "header outside the scope is refused", ctx: ctxWithHeader("zzz"), scope: several, wantErr: idtenantscope.ErrActingOrganizationNotPermitted},
		{name: "several and nothing named is ambiguous", ctx: ctxWithHeader(""), scope: several, wantErr: idtenantscope.ErrAmbiguousActingOrganization},
		{name: "platform admin naming nothing is ambiguous", ctx: ctxWithHeader(""), scope: Scope{PlatformAdmin: true}, wantErr: idtenantscope.ErrAmbiguousActingOrganization},
		{name: "platform admin's header is accepted unverified here", ctx: ctxWithHeader("anything"), scope: Scope{PlatformAdmin: true}, want: "anything"},
		{name: "empty scope has nothing to act in", ctx: ctxWithHeader(""), scope: Scope{}, wantErr: idtenantscope.ErrNoActingOrganization},
		{name: "nil context uses the implicit rule", ctx: nil, scope: Scope{OrgIDs: []string{"a"}}, want: "a"},
		{name: "nil context with several is ambiguous", ctx: nil, scope: several, wantErr: idtenantscope.ErrAmbiguousActingOrganization},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ActingOrganization(tc.ctx, tc.scope, tc.requested)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
