package api

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
			if got := redactSensitivePath(tc.in); got != tc.want {
				t.Errorf("redactSensitivePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
