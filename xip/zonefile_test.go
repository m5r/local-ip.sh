package xip

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	testZoneFileName = "test.zone"
	testOrigin       = "example.test"
)

var testServer = zoneServer{
	origin:    testOrigin,
	reserved:  []string{"NS1.Example.Test.", "ns2.example.test", `\095acme-challenge.example.test.`},
	addresses: []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("2001:db8:ffff::10")},
}

type wantDelegation struct {
	nameServers []string
	glue        []string
}

func rrString(t *testing.T, record string) string {
	t.Helper()
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatalf("parsing expected record %q: %v", record, err)
	}
	return rr.String()
}

func rrStrings(t *testing.T, records ...string) []string {
	t.Helper()
	strs := make([]string, len(records))
	for i, record := range records {
		strs[i] = rrString(t, record)
	}
	return strs
}

func stringsOf(rrs []dns.RR) []string {
	strs := make([]string, len(rrs))
	for i, rr := range rrs {
		strs[i] = rr.String()
	}
	return strs
}

func TestParseDelegationsAcceptsValidFiles(t *testing.T) {
	singleNS := func(t *testing.T) map[string]wantDelegation {
		return map[string]wantDelegation{
			"sub.example.test.": {
				nameServers: rrStrings(t, "sub.example.test. 300 IN NS ns1.sub.example.test."),
				glue:        rrStrings(t, "ns1.sub.example.test. 300 IN A 192.0.2.1"),
			},
		}
	}

	tests := []struct {
		name    string
		content string
		want    func(t *testing.T) map[string]wantDelegation
	}{
		{
			name:    "one in-cut name server with A glue",
			content: "sub NS ns1.sub\nns1.sub A 192.0.2.1\n",
			want:    singleNS,
		},
		{
			name:    "absolute names give the same result as relative names",
			content: "sub.example.test. NS ns1.sub.example.test.\nns1.sub.example.test. A 192.0.2.1\n",
			want:    singleNS,
		},
		{
			name:    "mixed-case owners and targets are canonicalised",
			content: "SuB NS Ns1.SUB\nnS1.sUb.ExAmPlE.tEsT. A 192.0.2.1\n",
			want:    singleNS,
		},
		{
			name:    "name server outside the zone needs no glue, in-cut name server has A and AAAA glue",
			content: "sub NS ns.other.test.\nsub NS ns1.sub\nns1.sub A 192.0.2.1\nns1.sub AAAA 2001:db8::1\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"sub.example.test.": {
						nameServers: rrStrings(t, "sub.example.test. 300 IN NS ns.other.test.", "sub.example.test. 300 IN NS ns1.sub.example.test."),
						glue:        rrStrings(t, "ns1.sub.example.test. 300 IN A 192.0.2.1", "ns1.sub.example.test. 300 IN AAAA 2001:db8::1"),
					},
				}
			},
		},
		{
			name:    "$TTL directive is honoured",
			content: "$TTL 600\nsub NS ns1.sub\nns1.sub A 192.0.2.1\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"sub.example.test.": {
						nameServers: rrStrings(t, "sub.example.test. 600 IN NS ns1.sub.example.test."),
						glue:        rrStrings(t, "ns1.sub.example.test. 600 IN A 192.0.2.1"),
					},
				}
			},
		},
		{
			name:    "explicit per-record TTL is honoured",
			content: "sub 120 NS ns1.sub\nns1.sub 60 A 192.0.2.1\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"sub.example.test.": {
						nameServers: rrStrings(t, "sub.example.test. 120 IN NS ns1.sub.example.test."),
						glue:        rrStrings(t, "ns1.sub.example.test. 60 IN A 192.0.2.1"),
					},
				}
			},
		},
		{
			name:    "cut two labels below the apex",
			content: "a.b NS ns1.a.b\nns1.a.b A 192.0.2.1\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"a.b.example.test.": {
						nameServers: rrStrings(t, "a.b.example.test. 300 IN NS ns1.a.b.example.test."),
						glue:        rrStrings(t, "ns1.a.b.example.test. 300 IN A 192.0.2.1"),
					},
				}
			},
		},
		{
			name:    "name server equal to the cut with glue at the cut",
			content: "sub NS sub\nsub A 192.0.2.1\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"sub.example.test.": {
						nameServers: rrStrings(t, "sub.example.test. 300 IN NS sub.example.test."),
						glue:        rrStrings(t, "sub.example.test. 300 IN A 192.0.2.1"),
					},
				}
			},
		},
		{
			name:    "two cuts",
			content: "one NS ns.other.test.\ntwo NS ns1.two\nns1.two A 192.0.2.2\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					"one.example.test.": {
						nameServers: rrStrings(t, "one.example.test. 300 IN NS ns.other.test."),
					},
					"two.example.test.": {
						nameServers: rrStrings(t, "two.example.test. 300 IN NS ns1.two.example.test."),
						glue:        rrStrings(t, "ns1.two.example.test. 300 IN A 192.0.2.2"),
					},
				}
			},
		},
		{
			name:    "names spelled with decimal escapes are the plain names",
			content: `\115ub NS ns1.\115UB` + "\n" + `\110s1.sub A 192.0.2.1` + "\n",
			want:    singleNS,
		},
		{
			name:    "label with an escaped dot",
			content: `a\.b NS ns1.a\.b` + "\n" + `ns1.a\.b A 192.0.2.1` + "\n",
			want: func(t *testing.T) map[string]wantDelegation {
				return map[string]wantDelegation{
					`a\.b.example.test.`: {
						nameServers: rrStrings(t, `a\.b.example.test. 300 IN NS ns1.a\.b.example.test.`),
						glue:        rrStrings(t, `ns1.a\.b.example.test. 300 IN A 192.0.2.1`),
					},
				}
			},
		},
		{
			name:    "empty file",
			content: "",
			want:    func(*testing.T) map[string]wantDelegation { return nil },
		},
		{
			name:    "comments only",
			content: "; nothing is delegated\n\n   ; still nothing\n",
			want:    func(*testing.T) map[string]wantDelegation { return nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDelegations(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err != nil {
				t.Fatalf("parseDelegations: %v", err)
			}
			want := tt.want(t)
			if got.apex != "example.test." {
				t.Errorf("apex = %q, want %q", got.apex, "example.test.")
			}
			if gotCuts, wantCuts := got.sortedCuts(), slices.Sorted(maps.Keys(want)); !slices.Equal(gotCuts, wantCuts) {
				t.Fatalf("cuts = %v, want %v", gotCuts, wantCuts)
			}
			for cut, w := range want {
				d := got.cuts[cut]
				if gotNS := stringsOf(d.nameServers); !slices.Equal(gotNS, w.nameServers) {
					t.Errorf("%s name servers = %q, want %q", cut, gotNS, w.nameServers)
				}
				if gotGlue := stringsOf(d.glue); !slices.Equal(gotGlue, w.glue) {
					t.Errorf("%s glue = %q, want %q", cut, gotGlue, w.glue)
				}
			}
		})
	}
}

func TestParseDelegationsRejectsInvalidFiles(t *testing.T) {
	const validDelegation = "sub NS ns1.sub\nns1.sub A 192.0.2.1\n"

	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name:    "R1 class other than IN",
			content: "sub CH NS ns.other.test.\n",
			want:    []string{"sub.example.test. NS", "class CH"},
		},
		{
			name:    "R2 record owned by the apex",
			content: "@ NS ns.other.test.\n",
			want:    []string{"example.test. NS", "strictly below the apex"},
		},
		{
			name:    "R2 record outside the zone",
			content: "sub.other.test. NS ns.other.test.\n",
			want:    []string{"sub.other.test. NS", "strictly below the apex"},
		},
		{
			name:    "R3 wildcard owner",
			content: "*.sub NS ns.other.test.\n",
			want:    []string{"*.sub.example.test. NS", "wildcard"},
		},
		{
			name:    "R3 wildcard label spelled with a decimal escape",
			content: `\042.sub NS ns.other.test.` + "\n",
			want:    []string{"*.sub.example.test. NS", "wildcard"},
		},
		{
			name:    "R4 CNAME record",
			content: "sub CNAME other.test.\n",
			want:    []string{"sub.example.test. CNAME", "only delegations are supported"},
		},
		{
			name:    "R4 SOA record",
			content: "@ SOA ns1 admin 1 900 900 1800 300\n",
			want:    []string{"example.test. SOA", "only delegations are supported"},
		},
		{
			name:    "R4 TXT record",
			content: validDelegation + "sub TXT \"hello\"\n",
			want:    []string{"sub.example.test. TXT", "only delegations are supported"},
		},
		{
			name:    "R5 cut below another cut",
			content: "sub NS ns.other.test.\na.sub NS ns.other.test.\n",
			want:    []string{"a.sub.example.test. NS", "nested below the delegation sub.example.test."},
		},
		{
			name:    "R5 cut below another cut declared first",
			content: "a.sub NS ns.other.test.\nsub NS ns.other.test.\n",
			want:    []string{"a.sub.example.test. NS", "nested below the delegation sub.example.test."},
		},
		{
			name:    "R5 cut below another cut spelled with a decimal escape",
			content: "sub NS ns.other.test.\n" + `a.\115ub NS ns.other.test.` + "\n",
			want:    []string{"a.sub.example.test. NS", "nested below the delegation sub.example.test."},
		},
		{
			name:    "R6 cut spelled with decimal escapes equal to a name server of the server",
			content: `\110\115\049 NS ns.other.test.` + "\n",
			want:    []string{"ns1.example.test. NS", "reserved"},
		},
		{
			name:    "R6 cut equal to a name server of the server",
			content: "ns1 NS ns.other.test.\n",
			want:    []string{"ns1.example.test. NS", "reserved"},
		},
		{
			name:    "R6 cut equal to a non-canonical reserved name",
			content: "ns2 NS ns.other.test.\n",
			want:    []string{"ns2.example.test. NS", "reserved"},
		},
		{
			name:    "R6 cut equal to the ACME challenge name, reserved with a decimal escape",
			content: "_acme-challenge NS ns.other.test.\n",
			want:    []string{"_acme-challenge.example.test. NS", "reserved"},
		},
		{
			name:    "R7 name server elsewhere inside the zone",
			content: "sub NS ns.other\nns.other A 192.0.2.1\n",
			want:    []string{"sub.example.test. NS", "name server ns.other.example.test. is inside the zone"},
		},
		{
			name:    "R7 name server spelled with a decimal escape is one of the server's own name servers",
			content: `sub NS ns1.\101xample.test.` + "\n",
			want:    []string{"sub.example.test. NS", "name server ns1.example.test. is inside the zone"},
		},
		{
			name:    "R7 name server is the apex",
			content: "sub NS @\n",
			want:    []string{"sub.example.test. NS", "name server example.test. is inside the zone"},
		},
		{
			name:    "R7 name server is one of the server's own name servers",
			content: "sub NS ns1\n",
			want:    []string{"sub.example.test. NS", "name server ns1.example.test. is inside the zone"},
		},
		{
			name:    "R7 two cuts whose name servers sit inside each other",
			content: "one NS ns.two\ntwo NS ns.one\nns.one A 192.0.2.1\nns.two A 192.0.2.2\n",
			want:    []string{"one.example.test. NS", "name server ns.two.example.test. is inside the zone"},
		},
		{
			name:    "R8 in-cut name server without glue",
			content: "sub NS ns1.sub\n",
			want:    []string{"sub.example.test. NS", "no A or AAAA glue"},
		},
		{
			name:    "R9 address record not inside any cut",
			content: validDelegation + "www A 192.0.2.2\n",
			want:    []string{"www.example.test. A", "not inside any delegation"},
		},
		{
			name:    "R9 address record inside a cut that is not a name server",
			content: validDelegation + "www.sub AAAA 2001:db8::2\n",
			want:    []string{"www.sub.example.test. AAAA", "not glue"},
		},
		{
			name:    "R10 duplicate record",
			content: validDelegation + "ns1.sub A 192.0.2.1\n",
			want:    []string{"ns1.sub.example.test. A", "duplicate"},
		},
		{
			name:    "R10 duplicate record differing only in case and TTL",
			content: "sub NS ns.other.test.\nSUB 600 NS NS.OTHER.TEST.\n",
			want:    []string{"sub.example.test. NS", "duplicate"},
		},
		{
			name:    "R10 duplicate record spelled with a decimal escape",
			content: "sub NS ns.other.test.\n" + `\115ub NS ns.other.test.` + "\n",
			want:    []string{"sub.example.test. NS", "duplicate"},
		},
		{
			name:    "R11 records of one RRset with different TTLs",
			content: "sub 300 NS a.other.test.\nsub 600 NS b.other.test.\n",
			want:    []string{"sub.example.test. NS", "TTL 600 differs from TTL 300"},
		},
		{
			name:    "R12 referral larger than a UDP response",
			content: manyNameServers(10),
			want:    []string{"delegation sub.example.test.", "more than the limit of 512 octets"},
		},
		{
			name:    "R13 A glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub A 198.51.100.10\n",
			want:    []string{"ns1.sub.example.test. A", "198.51.100.10", "own name server addresses"},
		},
		{
			name:    "R13 AAAA glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub AAAA 2001:db8:ffff::10\n",
			want:    []string{"ns1.sub.example.test. AAAA", "2001:db8:ffff::10", "own name server addresses"},
		},
		{
			name:    "R13 IPv4-mapped AAAA glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub AAAA ::ffff:198.51.100.10\n",
			want:    []string{"ns1.sub.example.test. AAAA", "198.51.100.10", "own name server addresses"},
		},
		{
			name:    "syntax error",
			content: "sub NS ns1.sub\nns1.sub A not-an-address\n",
			want:    []string{"parsing zone file", "not-an-address"},
		},
		{
			name:    "NS record without a target",
			content: "sub NS\n",
			want:    []string{"sub.example.test. NS", "no data"},
		},
		{
			name:    "A record without an address",
			content: "sub NS ns1.sub\nns1.sub A\n",
			want:    []string{"ns1.sub.example.test. A", "no data"},
		},
		{
			name:    "AAAA record without an address",
			content: "sub NS ns1.sub\nns1.sub AAAA\n",
			want:    []string{"ns1.sub.example.test. AAAA", "no data"},
		},
		{
			name:    "$INCLUDE directive",
			content: "$INCLUDE other.zone\n",
			want:    []string{"parsing zone file", "$INCLUDE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDelegations(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err == nil {
				t.Fatalf("parseDelegations succeeded with delegations %v, want an error", got.sortedCuts())
			}
			if got != nil {
				t.Errorf("parseDelegations returned delegations %v together with an error", got)
			}
			for _, want := range append([]string{testZoneFileName}, tt.want...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func manyNameServers(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "sub NS ns%d.sub\nns%d.sub A 192.0.2.%d\n", i, i, i+1)
	}
	return b.String()
}

func TestParseDelegationsReferralSizeBoundary(t *testing.T) {
	tests := []struct {
		name    string
		content string
		fits    bool
	}{
		{name: "production-shaped delegation", content: "staging NS ns1.staging\nns1.staging A 149.248.203.129\n", fits: true},
		{name: "largest number of name servers that fits", content: manyNameServers(largestFittingNameServerCount(t)), fits: true},
		{name: "one name server more", content: manyNameServers(largestFittingNameServerCount(t) + 1), fits: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDelegations(strings.NewReader(tt.content), testZoneFileName, testServer)
			if tt.fits && err != nil {
				t.Fatalf("parseDelegations: %v", err)
			}
			if !tt.fits && err == nil {
				t.Fatal("parseDelegations succeeded, want an error about the referral size")
			}
		})
	}
}

// largestFittingNameServerCount packs the referrals independently of parseDelegations, so the
// boundary test does not trust the code under test to find the boundary.
func largestFittingNameServerCount(t *testing.T) int {
	t.Helper()
	qname := strings.ToUpper(strings.Repeat("x", 63) + "." + strings.Repeat("x", 63) + "." + strings.Repeat("x", 63) + "." + strings.Repeat("x", 44) + ".sub.example.test.")
	for n := 1; ; n++ {
		msg := new(dns.Msg)
		msg.SetQuestion(qname, dns.TypeA)
		msg.Compress = true
		for i := range n {
			msg.Ns = append(msg.Ns, mustRR(t, fmt.Sprintf("sub.example.test. 300 IN NS ns%d.sub.example.test.", i)))
			msg.Extra = append(msg.Extra, mustRR(t, fmt.Sprintf("ns%d.sub.example.test. 300 IN A 192.0.2.%d", i, i+1)))
		}
		packed, err := msg.Pack()
		if err != nil {
			t.Fatalf("packing referral: %v", err)
		}
		if len(packed) > dns.MinMsgSize {
			return n - 1
		}
	}
}

func mustRR(t *testing.T, record string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatalf("parsing %q: %v", record, err)
	}
	return rr
}

func TestLongestNameIn(t *testing.T) {
	for _, cut := range []string{"sub.example.test.", "a.b.c.example.test.", "staging.local-ip.sh.", "x.example.test."} {
		t.Run(cut, func(t *testing.T) {
			name, err := longestNameIn(cut)
			if err != nil {
				t.Fatal(err)
			}
			if !dns.IsSubDomain(cut, name) {
				t.Fatalf("%s is not inside %s", name, cut)
			}
			if _, ok := dns.IsDomainName(name); !ok {
				t.Fatalf("%s is not a valid domain name", name)
			}
			buf := make([]byte, 512)
			length, err := dns.PackDomainName(name, buf, 0, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if length != maxNameWireLength {
				t.Errorf("wire length of %s = %d, want %d", name, length, maxNameWireLength)
			}
		})
	}
}

func TestReferralProbeName(t *testing.T) {
	cuts := []string{
		"sub.example.test.",
		"a.b.c.example.test.",
		"\u017fub.example.test.",
		"\u0131\u0131\u0131.example.test.",
	}
	for _, cut := range cuts {
		t.Run(cut, func(t *testing.T) {
			name, err := referralProbeName(cut)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			length, err := dns.PackDomainName(name, buf, 0, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if length != maxNameWireLength {
				t.Errorf("wire length of the probe name %q = %d, want %d", name, length, maxNameWireLength)
			}
			if !strings.HasSuffix(name, upperASCII(cut)) {
				t.Errorf("probe name %q does not end with the cut %q in ASCII upper case", name, cut)
			}
			if strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyz") {
				t.Errorf("probe name %q contains lower-case ASCII letters", name)
			}
		})
	}
}

func TestFindDelegation(t *testing.T) {
	parse := func(content string) *zoneCuts {
		t.Helper()
		zc, err := parseDelegations(strings.NewReader(content), testZoneFileName, testServer)
		if err != nil {
			t.Fatal(err)
		}
		return zc
	}
	staging := parse("staging NS ns1.staging\nns1.staging A 192.0.2.1\n")
	escapedDot := parse(`a\.b NS ns.other.test.` + "\n")

	tests := []struct {
		name    string
		zc      *zoneCuts
		query   string
		wantCut string
	}{
		{name: "the cut itself", zc: staging, query: "staging.example.test.", wantCut: "staging.example.test."},
		{name: "one label below", zc: staging, query: "www.staging.example.test.", wantCut: "staging.example.test."},
		{name: "three labels below", zc: staging, query: "a.b.c.staging.example.test.", wantCut: "staging.example.test."},
		{name: "mixed case and not fully qualified", zc: staging, query: "WwW.StAgInG.eXaMpLe.TeSt", wantCut: "staging.example.test."},
		{name: "sibling with a longer first label", zc: staging, query: "xstaging.example.test."},
		{name: "sibling sharing a suffix", zc: staging, query: "notstaging.example.test."},
		{name: "apex", zc: staging, query: "example.test."},
		{name: "outside the zone", zc: staging, query: "staging.example.com."},
		{name: "label with an escaped dot covers names below it", zc: escapedDot, query: `x.a\.b.example.test.`, wantCut: `a\.b.example.test.`},
		{name: "label with an escaped dot is one label", zc: escapedDot, query: "b.example.test."},
		{name: "label with an escaped dot does not cover its last part", zc: escapedDot, query: "x.b.example.test."},
		{name: "no cuts", zc: &zoneCuts{apex: "example.test.", cuts: map[string]delegation{}}, query: "staging.example.test."},
		{name: "nil", zc: nil, query: "staging.example.test."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCut, d, ok := tt.zc.find(tt.query)
			if ok != (tt.wantCut != "") {
				t.Fatalf("find(%q) = %q, %t; want %q", tt.query, gotCut, ok, tt.wantCut)
			}
			if !ok {
				return
			}
			if gotCut != tt.wantCut {
				t.Errorf("cut = %q, want %q", gotCut, tt.wantCut)
			}
			if len(d.nameServers) != 1 {
				t.Errorf("got %d name servers, want 1", len(d.nameServers))
			}
		})
	}
}

// TestRepositoryZoneFiles loads the zone files delivered to the deployments the way their servers
// do, so a file that would stop a server at startup fails here first.
func TestRepositoryZoneFiles(t *testing.T) {
	tests := []struct {
		file      string
		origin    string
		reserved  []string
		addresses []netip.Addr
		cuts      []string
	}{
		{
			file:      "local-ip.sh.zone",
			origin:    "local-ip.sh",
			reserved:  []string{"ns1.local-ip.sh.", "ns2.local-ip.sh.", "_acme-challenge.local-ip.sh."},
			addresses: []netip.Addr{netip.MustParseAddr("137.66.40.11"), netip.MustParseAddr("137.66.40.12")},
			cuts:      []string{"staging.local-ip.sh."},
		},
		{
			file:      "staging.local-ip.sh.zone",
			origin:    "staging.local-ip.sh",
			reserved:  []string{"ns1.staging.local-ip.sh.", "_acme-challenge.staging.local-ip.sh."},
			addresses: []netip.Addr{netip.MustParseAddr("149.248.203.129")},
			cuts:      []string{"e2e-delegated.staging.local-ip.sh."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("..", "zones", tt.file)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			delegations, err := parseDelegations(strings.NewReader(string(content)), path, zoneServer{origin: tt.origin, reserved: tt.reserved, addresses: tt.addresses})
			if err != nil {
				t.Fatal(err)
			}
			if got := delegations.sortedCuts(); !slices.Equal(got, tt.cuts) {
				t.Errorf("cuts = %v, want %v", got, tt.cuts)
			}
		})
	}
}
