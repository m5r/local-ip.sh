package names

import (
	"fmt"
	"strings"
	"testing"
)

func TestCanonical(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	name237 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 45)
	name238 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 46)
	if len(name237) != MaxLength || len(name238) != MaxLength+1 {
		t.Fatalf("test names have lengths %d and %d, want %d and %d", len(name237), len(name238), MaxLength, MaxLength+1)
	}

	tests := []struct {
		domain string
		want   string
		reason string
	}{
		{domain: "local-ip.sh", want: "local-ip.sh"},
		{domain: "Local-IP.SH.", want: "local-ip.sh"},
		{domain: "xip-staging.local-ip.sh", want: "xip-staging.local-ip.sh"},
		{domain: "localhost", want: "localhost"},
		{domain: "123.example", want: "123.example"},
		{domain: label63 + ".sh", want: label63 + ".sh"},
		{domain: name237, want: name237},

		{domain: "", reason: "empty"},
		{domain: ".", reason: "empty"},
		{domain: "..", reason: "empty label"},
		{domain: "...", reason: "empty label"},
		{domain: "a..b", reason: "empty label"},
		{domain: ".a", reason: "empty label"},
		{domain: "a.b..", reason: "empty label"},
		{domain: "-a.b", reason: `label "-a" starts or ends with a hyphen`},
		{domain: "a-.b", reason: `label "a-" starts or ends with a hyphen`},
		{domain: "a_b.c", reason: `character '_' (U+005F) is not a letter, a digit, a hyphen or a dot`},
		{domain: "a b.c", reason: `character ' ' (U+0020) is not a letter, a digit, a hyphen or a dot`},
		{domain: "a/b", reason: `character '/' (U+002F) is not a letter, a digit, a hyphen or a dot`},
		{domain: "../x", reason: `character '/' (U+002F) is not a letter, a digit, a hyphen or a dot`},
		{domain: label64 + ".sh", reason: "label longer than 63 bytes"},
		{domain: name238, reason: "longer than 237 bytes"},
		{domain: "é.fr", reason: `character 'é' (U+00E9) is not a letter, a digit, a hyphen or a dot`},
		{domain: "\u212a.fr", reason: "character '\u212a' (U+212A) is not a letter, a digit, a hyphen or a dot"},
		{domain: "a\xffb.c", reason: "character '\ufffd' (U+FFFD) is not a letter, a digit, a hyphen or a dot"},
		{domain: "1.2.3.4", reason: "an IP address"},
		{domain: "::1", reason: "an IP address"},
	}
	for _, tt := range tests {
		got, err := Canonical(tt.domain)
		if tt.reason == "" {
			if err != nil {
				t.Errorf("Canonical(%q) returned error %v, want %q", tt.domain, err, tt.want)
			} else if got != tt.want {
				t.Errorf("Canonical(%q) = %q, want %q", tt.domain, got, tt.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("Canonical(%q) = %q, want an error naming %q", tt.domain, got, tt.reason)
			continue
		}
		if want := fmt.Sprintf("invalid domain %q: %s", tt.domain, tt.reason); err.Error() != want {
			t.Errorf("Canonical(%q) error = %q, want %q", tt.domain, err, want)
		}
		if got != "" {
			t.Errorf("Canonical(%q) returned %q alongside its error, want empty", tt.domain, got)
		}
	}
}
