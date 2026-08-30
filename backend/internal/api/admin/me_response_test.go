package admin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sethbacon/terraform-suite-identity/identity/models"
)

// The /auth/me wire format, pinned as JSON.
//
// Asserted as exact JSON rather than by poking at struct fields, because the
// defect this closes was a struct that did not match the bytes on the wire
// (#892). A test that checked the struct would have agreed with the struct and
// missed it entirely -- the swagger annotation already "agreed" with the struct
// for months while describing a shape no client ever received.
//
// The two null-vs-absent distinctions below are the substance:
//   - role_template, at both levels, is PRESENT and null when there is none
//   - session_expires_at is ABSENT when there is none
// Getting either backwards is a silent contract change, which is why they are
// separate cases rather than one happy path.

func strPtr(s string) *string { return &s }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

var meFixedTime = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func meUser() *models.User {
	return &models.User{
		ID: "u1", Email: "a@b.c", Name: "Alice",
		CreatedAt: meFixedTime, UpdatedAt: meFixedTime,
	}
}

func TestBuildMeResponse_WireFormat(t *testing.T) {
	for _, tc := range []struct {
		name        string
		memberships []models.UserMembership
		expires     *time.Time
		want        string
	}{
		{
			name: "membership with a role template",
			memberships: []models.UserMembership{{
				OrganizationID: "o1", OrganizationName: "Org One",
				RoleTemplateID: strPtr("rt1"), RoleTemplateName: strPtr("owner"),
				RoleTemplateDisplayName: strPtr("Owner"),
				RoleTemplateScopes:      []string{"admin"},
				CreatedAt:               meFixedTime,
			}},
			want: `{"user":{"id":"u1","email":"a@b.c","name":"Alice","created_at":"2026-08-24T12:00:00Z","updated_at":"2026-08-24T12:00:00Z"},` +
				`"memberships":[{"organization_id":"o1","organization_name":"Org One","created_at":"2026-08-24T12:00:00Z",` +
				`"role_template":{"id":"rt1","name":"owner","display_name":"Owner","scopes":["admin"]}}],` +
				`"allowed_scopes":["admin"],"role_template":{"name":"owner","display_name":"Owner"}}`,
		},
		{
			// role_template is PRESENT and null, at both levels.
			name: "membership with no role template",
			memberships: []models.UserMembership{{
				OrganizationID: "o1", OrganizationName: "Org One", CreatedAt: meFixedTime,
			}},
			want: `{"user":{"id":"u1","email":"a@b.c","name":"Alice","created_at":"2026-08-24T12:00:00Z","updated_at":"2026-08-24T12:00:00Z"},` +
				`"memberships":[{"organization_id":"o1","organization_name":"Org One","created_at":"2026-08-24T12:00:00Z","role_template":null}],` +
				`"allowed_scopes":["admin"],"role_template":null}`,
		},
		{
			// memberships is [] and not null.
			name:        "no memberships at all",
			memberships: nil,
			want: `{"user":{"id":"u1","email":"a@b.c","name":"Alice","created_at":"2026-08-24T12:00:00Z","updated_at":"2026-08-24T12:00:00Z"},` +
				`"memberships":[],"allowed_scopes":["admin"],"role_template":null}`,
		},
		{
			// session_expires_at is the one field that IS omitted when absent —
			// contrast every role_template above.
			//
			// session_expires_in is absent here for a REASON worth stating, because
			// this is an exact-wire-format assertion: meFixedTime is in the past, so
			// the remaining lifetime is non-positive and the builder omits it. Move
			// this fixture into the future and this case must gain the field —
			// TestBuildMeResponse_SessionExpiresIn below covers that direction.
			name:        "with a session expiry",
			memberships: nil,
			expires:     &meFixedTime,
			want: `{"user":{"id":"u1","email":"a@b.c","name":"Alice","created_at":"2026-08-24T12:00:00Z","updated_at":"2026-08-24T12:00:00Z"},` +
				`"memberships":[],"allowed_scopes":["admin"],"role_template":null,"session_expires_at":"2026-08-24T12:00:00Z"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustJSON(t, buildMeResponse(meUser(), tc.memberships, []string{"admin"}, tc.expires))
			if got != tc.want {
				t.Errorf("wire format changed.\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestMeResponse_RoundTripsIntoItsOwnStruct is the check the issue asked for as
// the minimum: whatever the handler emits must unmarshal back into the type the
// swagger annotation names. If the two ever diverge again, this fails.
func TestMeResponse_RoundTripsIntoItsOwnStruct(t *testing.T) {
	built := buildMeResponse(meUser(), []models.UserMembership{{
		OrganizationID: "o1", OrganizationName: "Org One",
		RoleTemplateID: strPtr("rt1"), RoleTemplateName: strPtr("owner"),
		RoleTemplateDisplayName: strPtr("Owner"), RoleTemplateScopes: []string{"admin"},
		CreatedAt: meFixedTime,
	}}, []string{"admin"}, nil)

	var back MeResponse
	if err := json.Unmarshal([]byte(mustJSON(t, built)), &back); err != nil {
		t.Fatalf("the emitted body does not unmarshal into MeResponse: %v", err)
	}
	if mustJSON(t, back) != mustJSON(t, built) {
		t.Errorf("MeResponse does not round-trip.\n once: %s\ntwice: %s", mustJSON(t, built), mustJSON(t, back))
	}
	if back.Memberships[0].RoleTemplate == nil || back.Memberships[0].RoleTemplate.Name == nil {
		t.Fatal("the nested role_template was lost in the round trip")
	}
	if *back.Memberships[0].RoleTemplate.Name != "owner" {
		t.Errorf("role_template.name = %q, want \"owner\"", *back.Memberships[0].RoleTemplate.Name)
	}
}

// The remaining-lifetime field, which exists because session_expires_at alone is
// unusable against a browser clock that disagrees with ours: the client would be
// comparing our instant to its own Date.now(), wrong by exactly the skew. A
// duration we measure and it applies shares no clock (4cloudguru/cloud-suite-ui#181).
func TestBuildMeResponse_SessionExpiresIn(t *testing.T) {
	t.Run("a live expiry carries both the instant and the remaining seconds", func(t *testing.T) {
		exp := time.Now().Add(90 * time.Minute)
		got := buildMeResponse(meUser(), nil, []string{"admin"}, &exp)
		if got.SessionExpiresAt == nil {
			t.Fatal("SessionExpiresAt nil for a live expiry")
		}
		if got.SessionExpiresIn == nil {
			t.Fatal("SessionExpiresIn nil for a live expiry")
		}
		// Truncation toward zero costs at most a second; the builder does no I/O.
		if *got.SessionExpiresIn < 5390 || *got.SessionExpiresIn > 5400 {
			t.Errorf("SessionExpiresIn = %d, want ~5400 (90m)", *got.SessionExpiresIn)
		}
	})

	t.Run("a lapsed expiry omits the duration but keeps the instant", func(t *testing.T) {
		// A non-positive duration reads to the client as a real expiry and fails the
		// session closed, so it must never appear on a response we are answering 200.
		exp := time.Now().Add(-time.Minute)
		got := buildMeResponse(meUser(), nil, []string{"admin"}, &exp)
		if got.SessionExpiresAt == nil {
			t.Error("SessionExpiresAt dropped for a lapsed expiry; only the duration should be")
		}
		if got.SessionExpiresIn != nil {
			t.Errorf("SessionExpiresIn = %d for a lapsed expiry, want omitted", *got.SessionExpiresIn)
		}
	})

	t.Run("no expiry means neither field", func(t *testing.T) {
		got := buildMeResponse(meUser(), nil, []string{"admin"}, nil)
		if got.SessionExpiresAt != nil || got.SessionExpiresIn != nil {
			t.Errorf("expiry fields set without a claim: at=%v in=%v", got.SessionExpiresAt, got.SessionExpiresIn)
		}
	})

	t.Run("the emitted body still round-trips into MeResponse", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		built := buildMeResponse(meUser(), nil, []string{"admin"}, &exp)
		var back MeResponse
		if err := json.Unmarshal([]byte(mustJSON(t, built)), &back); err != nil {
			t.Fatalf("emitted body does not unmarshal into MeResponse: %v", err)
		}
		if back.SessionExpiresIn == nil || *back.SessionExpiresIn != *built.SessionExpiresIn {
			t.Errorf("SessionExpiresIn lost in round-trip: %v", back.SessionExpiresIn)
		}
	})
}
