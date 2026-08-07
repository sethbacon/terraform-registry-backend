package admin

import (
	"encoding/json"
	"testing"
)

// A full-replace PUT that omits "use_tls" must not be read as "disable TLS".
// As a plain bool it decoded to false and silently switched the relay to
// plaintext; the pointer makes absent distinguishable from an explicit false.
func TestUpdateNotificationsInput_OmittedUseTLSIsAbsentNotFalse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool
	}{
		{"omitted stays absent", `{"smtp":{"host":"relay","port":587}}`, nil},
		{"explicit false is honoured", `{"smtp":{"host":"relay","use_tls":false}}`, useTLSPtr(false)},
		{"explicit true is honoured", `{"smtp":{"host":"relay","use_tls":true}}`, useTLSPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var in notificationsConfigInput
			if err := json.Unmarshal([]byte(tc.body), &in); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := in.SMTP.UseTLS
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("omitted use_tls decoded to %v; absent must stay absent or a partial PUT silently disables TLS", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("explicit use_tls=%v decoded to nil; an explicit choice must survive", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("use_tls = %v, want %v", *got, *tc.want)
			}
		})
	}
}

func useTLSPtr(b bool) *bool { return &b }
