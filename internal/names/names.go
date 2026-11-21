// Package names holds the one definition of a domain this program can serve.
package names

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxLength is the longest domain Canonical accepts. The program builds _acme-challenge.<domain>, and a DNS name holds 253 bytes.
const MaxLength = 253 - len("_acme-challenge.")

const maxLabelLength = 63

// Canonical returns domain in lower case and without its trailing dot. It returns an error when the result is not a host name this program can serve: 1 to MaxLength bytes, made of labels of 1 to 63 ASCII letters, digits and hyphens that neither start nor end with a hyphen, and not an IP address.
//
// The result is safe to build DNS names, certificate names and file paths from. Whether a public certificate authority issues for it is another matter: a single label such as localhost is accepted.
func Canonical(domain string) (string, error) {
	invalid := func(reason string) (string, error) {
		return "", fmt.Errorf("invalid domain %q: %s", domain, reason)
	}

	name := strings.TrimSuffix(domain, ".")
	if name == "" {
		return invalid("empty")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return invalid("an IP address")
	}
	if len(name) > MaxLength {
		return invalid(fmt.Sprintf("longer than %d bytes", MaxLength))
	}

	// Validation comes before lowering because Unicode case folding would turn the Kelvin sign into k and let it pass.
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return invalid(fmt.Sprintf("character %q (%U) is not a letter, a digit, a hyphen or a dot", r, r))
		}
	}
	name = strings.ToLower(name)

	for label := range strings.SplitSeq(name, ".") {
		switch {
		case label == "":
			return invalid("empty label")
		case len(label) > maxLabelLength:
			return invalid(fmt.Sprintf("label longer than %d bytes", maxLabelLength))
		case label[0] == '-' || label[len(label)-1] == '-':
			return invalid(fmt.Sprintf("label %q starts or ends with a hyphen", label))
		}
	}
	return name, nil
}
