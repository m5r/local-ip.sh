package xip

import (
	"net/netip"
	"regexp"
	"strings"
)

var (
	dottedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
)

// addressIn returns the IPv4 address that labels carry. labels are the labels of a name below the zone apex in presentation form, each followed by its dot ("app.10-0-0-1."), and the empty string for the apex itself; letter case does not matter.
func addressIn(labels string) (netip.Addr, bool) {
	for _, ipV4RE := range []*regexp.Regexp{dashedIpV4Regex, dottedIpV4Regex} {
		match := ipV4RE.FindStringSubmatch(labels)
		if match == nil {
			continue
		}
		// The first expression that matches decides, even when its match is not an address, as it always has.
		addr, err := netip.ParseAddr(strings.ReplaceAll(match[1], "-", "."))
		if err != nil || !addr.Is4() {
			return netip.Addr{}, false
		}
		return addr, true
	}
	return netip.Addr{}, false
}
