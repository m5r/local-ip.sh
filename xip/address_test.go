package xip

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// addressInCases are examples of the rule, among them how a backslash and bytes outside ASCII read; want is empty for labels that carry no address.
var addressInCases = []struct {
	labels string
	want   string
	why    string
}{
	{labels: "", why: "the apex"},
	{labels: "10-0-0-1.", want: "10.0.0.1"},
	{labels: "10.0.0.1.", want: "10.0.0.1"},
	{labels: "app.10-0-0-1.", want: "10.0.0.1"},
	{labels: "foo.bar.10.0.0.1.", want: "10.0.0.1"},
	{labels: "app-10-0-0-1.", want: "10.0.0.1"},
	{labels: "my-app-10-0-0-1.", want: "10.0.0.1"},
	{labels: "10-0-0-1-app.", want: "10.0.0.1"},
	{labels: "a-10-0-0-1-b.", want: "10.0.0.1"},
	{labels: "foo.app-10-0-0-1.", want: "10.0.0.1"},
	{labels: "10-0-0-1.app.", want: "10.0.0.1"},
	{labels: "10.0.0.1.app.", want: "10.0.0.1"},
	{labels: "app.10.0.0.1.more.", want: "10.0.0.1"},
	{labels: "app-10.0.0.1.", want: "10.0.0.1"},
	{labels: "10.0.0.1-app.", want: "10.0.0.1"},
	{labels: "a-10.0.0.1-b.", want: "10.0.0.1"},
	{labels: "APP.10-0-0-1.WWW.", want: "10.0.0.1"},
	{labels: "0-0-0-0.", want: "0.0.0.0"},
	{labels: "255-255-255-255.", want: "255.255.255.255"},
	{labels: "10.0.0.1.10-0-0-2.", want: "10.0.0.2", why: "dashed before dotted"},
	{labels: "10-0-0-1.10-0-0-2.", want: "10.0.0.1", why: "leftmost dashed"},
	{labels: "10.0.0.1.10.0.0.2.", want: "10.0.0.1", why: "leftmost dotted"},
	{labels: "10-0-0-1-10-0-0-2.", want: "10.0.0.1"},
	{labels: "7-10-0-0-1.", want: "7.10.0.0", why: "five numbers"},
	{labels: "1.2.3.4.5.", want: "1.2.3.4"},
	{labels: "a-1-2-3-4.5-6-7-8.", want: "1.2.3.4"},
	{labels: "a-1-2-3-4.5.6.7.8.", want: "1.2.3.4"},
	{labels: "a-1.2.3.4.5.", want: "1.2.3.4"},
	{labels: "a!.1-2-3-4.5-6-7-8.", want: "1.2.3.4", why: "punctuation in the label before does not hide an address"},
	{labels: "1.2.3.4.app-5-6-7-8.", want: "5.6.7.8", why: "a dashed address after a dotted one"},
	{labels: "256-1-2-3-4.", want: "1.2.3.4"},
	{labels: "-10-0-0-1.", want: "10.0.0.1"},
	{labels: "10-0-0-1-.", want: "10.0.0.1"},
	{labels: "1-2.3.4.5-6.", want: "2.3.4.5"},
	{labels: "www.mail."},
	{labels: "10-0-0."},
	{labels: "10.0.0."},
	{labels: "app-10-0-0."},
	{labels: "10-0-0-256."},
	{labels: "10.0.256.1."},
	{labels: "10-0-00-1."},
	{labels: "10-0-01-1."},
	{labels: "10.0.01.1."},
	{labels: "010-0-0-1."},
	{labels: "10-0-0-1000."},
	{labels: "10--0-0-1."},
	{labels: "10-0.0-1.", why: "mixed separators"},
	{labels: "10-0-0.1."},
	{labels: "10.0-0.1."},
	{labels: "10-0-0-1x."},
	{labels: "x10-0-0-1."},
	{labels: "10_0_0_1."},
	{labels: "c0000201.", why: "hexadecimal"},
	{labels: `a\.10-0-0-1.`, why: "an escaped dot is not a separator"},
	{labels: `10-0-0-1\.app.`},
	{labels: `1\.2\.3\.4.`},
	{labels: `10-0-0-\049.`, why: "an escape makes no octet"},
	{labels: `10.0.0.\049.`},
	{labels: `app\.x-10-0-0-1.`, want: "10.0.0.1", why: "set off by the hyphen"},

	{labels: "\\", why: "one backslash"},
	{labels: "10-0-0-1\\", why: "a backslash ends the last part"},
	{labels: "10-0-0-1.\\", want: "10.0.0.1", why: "a backslash in a part of its own"},
	{labels: "10\\-0-0-1-2.", why: "an escaped hyphen is no separator"},
	{labels: "10\\.0.0.1.2.", why: "an escaped dot is no separator"},
	{labels: "\\12-3-4-5-6.", want: "3.4.5.6", why: "the escape is the backslash and one byte"},
	{labels: "\\123-4-5-6-7.", want: "4.5.6.7"},
	{labels: "\\\\.10-0-0-1.", want: "10.0.0.1", why: "an escaped backslash, then a dot that separates"},
	{labels: "10-0-0-1\\\\."},
	{labels: "10-0-0-1\n", why: "a line feed is a byte like any other"},
	{labels: "\n10-0-0-1."},
	{labels: "é-10-0-0-1.", want: "10.0.0.1"},
	{labels: "10-0-0-1é."},
	{labels: "\xff-10-0-0-1.", want: "10.0.0.1", why: "not UTF-8"},
	{labels: "10-0-0-1\xff."},
	{labels: "\\\xff-10-0-0-1.", want: "10.0.0.1", why: "a backslash and a byte that is not UTF-8"},
	{labels: "١٠-0-0-1.", why: "digits that are not ASCII"},

	{labels: "192-168-1-29.", want: "192.168.1.29"},
	{labels: "192.168.1.29.", want: "192.168.1.29"},
	{labels: "prefixed.192.168.1.29.", want: "192.168.1.29"},
	{labels: "prefixed-192.168.1.29.", want: "192.168.1.29", why: "a dotted address set off by a hyphen"},
	{labels: "prefixed-192-168-1-29.", want: "192.168.1.29", why: "a dashed address after text in its label"},
	{labels: "192-168-1-29.app.", want: "192.168.1.29"},
	{labels: "192.168.1.29.app.", want: "192.168.1.29"},
	{labels: "192-168-1-256."},
	{labels: "192.168.256.1."},
	{labels: "192-168-01-29."},
	{labels: "192.168.01.29."},
	{labels: "192-168-1."},
	{labels: "192.168.1."},
	{labels: "192-168-1-29-app.", want: "192.168.1.29"},
	{labels: "APP.192-168-1-29.WWW.", want: "192.168.1.29"},
	{labels: "APP.192.168.1.29.WWW.", want: "192.168.1.29"},
}

func TestAddressIn(t *testing.T) {
	for _, tt := range addressInCases {
		t.Run(strconv.Quote(tt.labels), func(t *testing.T) {
			addr, ok := addressIn(tt.labels)
			if ok != (tt.want != "") {
				t.Fatalf("addressIn(%q) = %v, %t; want %q (%s)", tt.labels, addr, ok, tt.want, tt.why)
			}
			if ok && addr.String() != tt.want {
				t.Errorf("addressIn(%q) = %v, want %s (%s)", tt.labels, addr, tt.want, tt.why)
			}
		})
	}
}

// These expressions are a second, independent formulation of the rule in addressIn's doc comment, used to check the scanner: every escape becomes a letter first, then the leftmost dashed address is taken, and without one the leftmost dotted address, each with a hyphen, a dot or an end of the string on both sides.
const octetExpression = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])`

var (
	escapeExpression = regexp.MustCompile(`\\(?:(?s:.)|$)`)
	dashedExpression = regexp.MustCompile(`(?:^|[.-])(` + octetExpression + `(?:-` + octetExpression + `){3})(?:$|[.-])`)
	dottedExpression = regexp.MustCompile(`(?:^|[.-])(` + octetExpression + `(?:\.` + octetExpression + `){3})(?:$|[.-])`)
)

func addressByTheDelimitedExpressions(labels string) (netip.Addr, bool) {
	unescaped := escapeExpression.ReplaceAllLiteralString(labels, "x")
	for _, expression := range []*regexp.Regexp{dashedExpression, dottedExpression} {
		if match := expression.FindStringSubmatch(unescaped); match != nil {
			return netip.MustParseAddr(strings.ReplaceAll(match[1], "-", ".")), true
		}
	}
	return netip.Addr{}, false
}

func TestAddressInAgreesWithTheDelimitedExpressions(t *testing.T) {
	for _, set := range []struct {
		name    string
		strings []string
	}{
		{"the parts", joinedSequences([]string{"1", "256", "a", ""}, []string{"-", "."}, 5, nil)},
		{"the arrangements", joinedSequences(nil, []string{"-", ".", ""}, 4, arrangementSegments)},
	} {
		t.Run(set.name, func(t *testing.T) {
			carrying, disagreements := 0, 0
			for _, labels := range set.strings {
				got, gotOK := addressIn(labels)
				want, wantOK := addressByTheDelimitedExpressions(labels)
				if wantOK {
					carrying++
				}
				if got == want && gotOK == wantOK {
					continue
				}
				t.Errorf("addressIn(%q) = %v, %t; the expressions give %v, %t", labels, got, gotOK, want, wantOK)
				if disagreements++; disagreements == 20 {
					t.Fatal("stopping after 20 disagreements")
				}
			}
			if carrying == 0 {
				t.Errorf("none of the %d strings carries an address by the expressions: the comparison checks nothing", len(set.strings))
			}
			t.Logf("%d strings, %d carry an address by the expressions", len(set.strings), carrying)
		})
	}
}

// joinedSequences returns every sequence of one to maxLength elements joined by every choice of separators, each with a dot at its end. The element at position n (from 1) is drawn from elements, or from elementsAt(n) when elements is nil.
func joinedSequences(elements, separators []string, maxLength int, elementsAt func(n int) []string) []string {
	var all []string
	var extend func(prefix string, n int)
	extend = func(prefix string, n int) {
		choices := elements
		if choices == nil {
			choices = elementsAt(n)
		}
		for _, element := range choices {
			sequence := prefix + element
			all = append(all, sequence+".")
			if n == maxLength {
				continue
			}
			for _, separator := range separators {
				extend(sequence+separator, n+1)
			}
		}
	}
	extend("", 1)
	return all
}

// arrangementSegments are the segments that can stand at position n of an arrangement; an address there has the octets 10n+1 to 10n+4, so that a result names the address it took.
func arrangementSegments(n int) []string {
	first := 10*n + 1
	return []string{
		fmt.Sprintf("%d-%d-%d-%d", first, first+1, first+2, first+3),
		fmt.Sprintf("%d.%d.%d.%d", first, first+1, first+2, first+3),
		"7",
		"256",
		"app",
		`\.`,
	}
}

func TestAddressInDoesNotAllocate(t *testing.T) {
	for _, labels := range []string{"app.10-0-0-1.", "foo.bar.10.0.0.1.", "www.mail.", `a\.b\0491-2-3-4\\.x.`} {
		if allocs := testing.AllocsPerRun(100, func() { addressIn(labels) }); allocs != 0 {
			t.Errorf("addressIn(%q) allocates %v times, want 0", labels, allocs)
		}
	}
}

func FuzzAddressIn(f *testing.F) {
	for _, tt := range addressInCases {
		f.Add(tt.labels)
	}
	f.Fuzz(func(t *testing.T, labels string) {
		got, gotOK := addressIn(labels)
		if gotOK && !got.Is4() {
			t.Fatalf("addressIn(%q) = %v, not an IPv4 address", labels, got)
		}
		want, wantOK := addressByTheDelimitedExpressions(labels)
		if got != want || gotOK != wantOK {
			t.Fatalf("addressIn(%q) = %v, %t; the expressions give %v, %t", labels, got, gotOK, want, wantOK)
		}
	})
}

func TestAddressInLabelsBelowTheApexOnly(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qname  string
		want   string
	}{
		{name: "a domain that carries an address gives no address to a name without one", domain: "10-0-0-1.example.test", qname: "app.10-0-0-1.example.test."},
		{name: "a domain that carries an address still resolves the address below it", domain: "10-0-0-1.example.test", qname: "10-0-0-2.10-0-0-1.example.test.", want: "10.0.0.2"},
		{name: "a domain that starts with a number does not complete three numbers below it", domain: "4.example.test", qname: "1.2.3.4.example.test."},
		{name: "a domain that starts with a number still resolves four numbers below it", domain: "4.example.test", qname: "9.1.2.3.4.example.test.", want: "9.1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := startTestServer(t,
				WithDomain(tt.domain),
				WithEmail("admin@example.test"),
				WithNameServers([]string{"192.0.2.10"}),
			)
			resp := queryTestServer(t, address, tt.qname, dns.TypeA)
			if tt.want == "" {
				if len(resp.Answer) != 0 {
					t.Errorf("got answers %q, want none", stringsOf(resp.Answer))
				}
				return
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want exactly 1:\n%s", len(resp.Answer), resp)
			}
			if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != tt.want {
				t.Errorf("answer = %q, want A %s", resp.Answer[0], tt.want)
			}
		})
	}
}
