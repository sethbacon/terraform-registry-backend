package middleware

import "testing"

func TestRedactSensitivePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "scm webhook secret redacted",
			in:   "/webhooks/scm/repo-123/s3cr3t-value",
			want: "/webhooks/scm/repo-123/[REDACTED]",
		},
		{
			name: "approval token redacted",
			in:   "/webhooks/approvals/tok_abc123",
			want: "/webhooks/approvals/[REDACTED]",
		},
		{
			name: "unrelated path untouched",
			in:   "/api/v1/modules/search",
			want: "/api/v1/modules/search",
		},
		{
			name: "webhook prefix but no secret segment untouched-ish",
			in:   "/webhooks/scm/",
			want: "/webhooks/scm/[REDACTED]",
		},
		{
			name: "non-webhook path with similar name",
			in:   "/api/webhooks/scm/x/y",
			want: "/api/webhooks/scm/x/y",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactSensitivePath(tc.in); got != tc.want {
				t.Errorf("RedactSensitivePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactSensitiveQuery(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty query untouched",
			in:   "",
			want: "",
		},
		{
			name: "oauth code and state redacted",
			in:   "code=abc123&state=userid:providerid",
			want: "code=%5BREDACTED%5D&state=%5BREDACTED%5D",
		},
		{
			name: "client_secret redacted",
			in:   "client_secret=s3cr3t",
			want: "client_secret=%5BREDACTED%5D",
		},
		{
			name: "non-sensitive params untouched",
			in:   "page=2&limit=50",
			want: "page=2&limit=50",
		},
		{
			name: "mixed sensitive and non-sensitive",
			in:   "page=2&token=tok_abc",
			want: "page=2&token=%5BREDACTED%5D",
		},
		{
			name: "malformed query redacted wholesale",
			in:   "%zz",
			want: "[REDACTED]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactSensitiveQuery(tc.in); got != tc.want {
				t.Errorf("RedactSensitiveQuery(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
