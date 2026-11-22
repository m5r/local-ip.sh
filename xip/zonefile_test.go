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
	origin:        testOrigin,
	nameServers:   []string{"NS1.Example.Test.", "ns2.example.test"},
	challengeName: `\095acme-challenge.example.test.`,
	addresses:     []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("2001:db8:ffff::10")},
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

// recordFault is the error parseZoneFile returns for a record of the test file that breaks a rule.
func recordFault(owner, rrtype, message string) string {
	return fmt.Sprintf("zone file %s: record %s %s: %s", testZoneFileName, owner, rrtype, message)
}

func TestParseZoneFileAcceptsDelegations(t *testing.T) {
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
			file, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err != nil {
				t.Fatalf("parseZoneFile: %v", err)
			}
			if len(file.records) != 0 {
				t.Errorf("records = %q, want none", stringsOf(file.records))
			}
			got := file.cuts
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

func TestParseZoneFileAcceptsRecords(t *testing.T) {
	long := strings.Repeat("a", 300)

	tests := []struct {
		name    string
		content string
		records []string
		cuts    []string
	}{
		{
			name:    "one record of each supported type below the apex",
			content: "sub NS ns.other.test.\nwww A 192.0.2.80\nwww AAAA 2001:db8::80\nwww CAA 0 issue \"letsencrypt.org\"\nalias CNAME target.other.test.\nwww MX 10 mail.other.test.\n_sip._tcp SRV 0 5 5060 sip.other.test.\nwww TXT \"hello\"\n",
			records: []string{
				"www.example.test. 300 IN A 192.0.2.80",
				"www.example.test. 300 IN AAAA 2001:db8::80",
				`www.example.test. 300 IN CAA 0 issue "letsencrypt.org"`,
				"alias.example.test. 300 IN CNAME target.other.test.",
				"www.example.test. 300 IN MX 10 mail.other.test.",
				"_sip._tcp.example.test. 300 IN SRV 0 5 5060 sip.other.test.",
				`www.example.test. 300 IN TXT "hello"`,
			},
			cuts: []string{"sub.example.test."},
		},
		{
			name:    "TXT, MX, AAAA, CAA and SRV records at the apex, in a file without a cut",
			content: "@ TXT \"v=spf1 -all\"\n@ MX 10 mail.other.test.\n@ AAAA 2001:db8::1\n@ CAA 0 issue \"letsencrypt.org\"\n@ SRV 0 5 5060 sip.other.test.\n",
			records: []string{
				`example.test. 300 IN TXT "v=spf1 -all"`,
				"example.test. 300 IN MX 10 mail.other.test.",
				"example.test. 300 IN AAAA 2001:db8::1",
				`example.test. 300 IN CAA 0 issue "letsencrypt.org"`,
				"example.test. 300 IN SRV 0 5 5060 sip.other.test.",
			},
		},
		{
			name:    "a TXT string of 300 octets arrives as two strings of 255 and 45 octets",
			content: "long TXT \"" + long + "\"\n",
			records: []string{fmt.Sprintf(`long.example.test. 300 IN TXT "%s" "%s"`, long[:255], long[255:])},
		},
		{
			name:    "a TXT string written with a decimal escape is stored as the wire gives it",
			content: `www TXT "\097"` + "\n",
			records: []string{`www.example.test. 300 IN TXT "a"`},
		},
		{
			name:    "a CAA record whose tag takes 255 octets",
			content: "www CAA 0 " + strings.Repeat("x", 255) + " \"v\"\n",
			records: []string{"www.example.test. 300 IN CAA 0 " + strings.Repeat("x", 255) + ` "v"`},
		},
		{
			name:    "a CAA value with an escaped backslash and the value it does not stand for are two records",
			content: `www CAA 0 example "\\097"` + "\n" + `www CAA 0 example "a"` + "\n",
			records: []string{`www.example.test. 300 IN CAA 0 example "\\097"`, `www.example.test. 300 IN CAA 0 example "a"`},
		},
		{
			name:    "a TXT record of one string and one of the same text in two strings are two records",
			content: "www TXT \"ab\"\nwww TXT \"a\" \"b\"\n",
			records: []string{`www.example.test. 300 IN TXT "ab"`, `www.example.test. 300 IN TXT "a" "b"`},
		},
		{
			name:    "a CAA record with an empty value, which authorises no issuer",
			content: `www CAA 0 issue ""` + "\n",
			records: []string{`www.example.test. 300 IN CAA 0 issue ""`},
		},
		{
			name:    "a TXT record of two strings stays one record with two strings",
			content: "multi TXT \"one\" \"two\"\n",
			records: []string{`multi.example.test. 300 IN TXT "one" "two"`},
		},
		{
			name:    "a null MX and an SRV record whose target is the root",
			content: "@ MX 0 .\n_sip._tcp SRV 0 0 0 .\n",
			records: []string{"example.test. 300 IN MX 0 .", "_sip._tcp.example.test. 300 IN SRV 0 0 0 ."},
		},
		{
			name:    "records and a delegation in one file",
			content: "www A 192.0.2.80\nsub NS ns1.sub\nns1.sub A 192.0.2.1\n@ TXT \"zone\"\n",
			records: []string{"www.example.test. 300 IN A 192.0.2.80", `example.test. 300 IN TXT "zone"`},
			cuts:    []string{"sub.example.test."},
		},
		{
			name:    "an address record outside every cut is a record of the zone",
			content: "sub NS ns1.sub\nns1.sub A 192.0.2.1\nwww A 192.0.2.2\n",
			records: []string{"www.example.test. 300 IN A 192.0.2.2"},
			cuts:    []string{"sub.example.test."},
		},
		{
			name:    "an address record equal to one of the server's own addresses outside every cut",
			content: "www A 198.51.100.10\n",
			records: []string{"www.example.test. 300 IN A 198.51.100.10"},
		},
		{
			name:    "a CNAME whose target is outside the zone",
			content: "alias CNAME target.other.test.\n",
			records: []string{"alias.example.test. 300 IN CNAME target.other.test."},
		},
		{
			name:    "a TXT record at the parent of a cut",
			content: "parent TXT \"above a cut\"\nchild.parent NS ns.other.test.\n",
			records: []string{`parent.example.test. 300 IN TXT "above a cut"`},
			cuts:    []string{"child.parent.example.test."},
		},
		{
			name:    "a CNAME record at the parent of a cut",
			content: "cparent CNAME target.other.test.\nchild.cparent NS ns.other.test.\n",
			records: []string{"cparent.example.test. 300 IN CNAME target.other.test."},
			cuts:    []string{"child.cparent.example.test."},
		},
		{
			name:    "glue whose owner carries an address",
			content: "addr NS 10-0-0-53.addr\n10-0-0-53.addr A 192.0.2.53\n",
			cuts:    []string{"addr.example.test."},
		},
		{
			name:    "a delegation at a name that carries an address",
			content: "10-0-0-1 NS ns.other.test.\n",
			cuts:    []string{"10-0-0-1.example.test."},
		},
		{
			name:    "owners in upper case and with a decimal escape and targets in mixed case are stored canonical",
			content: "UPPER TXT \"Upper\"\n" + `esc\065ped TXT "escaped"` + "\nWWW MX 10 Mail.Other.TEST.\nAlias CNAME Target.Other.Test.\n_SIP._TCP SRV 0 5 5060 SIP.other.test.\n",
			records: []string{
				`upper.example.test. 300 IN TXT "Upper"`,
				`escaped.example.test. 300 IN TXT "escaped"`,
				"www.example.test. 300 IN MX 10 mail.other.test.",
				"alias.example.test. 300 IN CNAME target.other.test.",
				"_sip._tcp.example.test. 300 IN SRV 0 5 5060 sip.other.test.",
			},
		},
		{
			name:    "records are returned in file order",
			content: "b TXT \"1\"\na A 192.0.2.1\nb A 192.0.2.2\n@ MX 10 a\na TXT \"2\"\nb TXT \"3\"\n",
			records: []string{
				`b.example.test. 300 IN TXT "1"`,
				"a.example.test. 300 IN A 192.0.2.1",
				"b.example.test. 300 IN A 192.0.2.2",
				"example.test. 300 IN MX 10 a.example.test.",
				`a.example.test. 300 IN TXT "2"`,
				`b.example.test. 300 IN TXT "3"`,
			},
		},
		{
			name:    "an MX record whose target is the apex",
			content: "@ MX 10 @\n",
			records: []string{"example.test. 300 IN MX 10 example.test."},
		},
		{
			name:    "an MX record whose target is a name server of the server",
			content: "@ MX 10 ns1\n",
			records: []string{"example.test. 300 IN MX 10 ns1.example.test."},
		},
		{
			name:    "an MX record whose target carries an address",
			content: "@ MX 10 10-0-0-1\n",
			records: []string{"example.test. 300 IN MX 10 10-0-0-1.example.test."},
		},
		{
			name:    "an MX record whose target carries an address after a name in its label",
			content: "@ MX 10 mail-10-0-0-1\n",
			records: []string{"example.test. 300 IN MX 10 mail-10-0-0-1.example.test."},
		},
		{
			name:    "an MX record whose target owns only an AAAA record",
			content: "@ MX 10 v6\nv6 AAAA 2001:db8::25\n",
			records: []string{"example.test. 300 IN MX 10 v6.example.test.", "v6.example.test. 300 IN AAAA 2001:db8::25"},
		},
		{
			name:    "an SRV record whose target owns an A record",
			content: "_sip._tcp SRV 0 5 5060 sip\nsip A 192.0.2.5\n",
			records: []string{"_sip._tcp.example.test. 300 IN SRV 0 5 5060 sip.example.test.", "sip.example.test. 300 IN A 192.0.2.5"},
		},
		{
			name:    "an MX record whose target is inside a delegation",
			content: "@ MX 10 mail.sub\nsub NS ns.other.test.\n",
			records: []string{"example.test. 300 IN MX 10 mail.sub.example.test."},
			cuts:    []string{"sub.example.test."},
		},
		{
			name:    "an MX record whose target is outside the zone",
			content: "@ MX 10 mail.other.test.\n",
			records: []string{"example.test. 300 IN MX 10 mail.other.test."},
		},
		{
			name:    "a name and a TXT string that contain $GENERATE",
			content: "x$GENERATE TXT \"x\"\nwww TXT \"$GENERATE 1-3 host$ A 192.0.2.$\"\n",
			records: []string{
				`x$generate.example.test. 300 IN TXT "x"`,
				`www.example.test. 300 IN TXT "$GENERATE 1-3 host$ A 192.0.2.$"`,
			},
		},
		{
			name:    "$ORIGIN moves the owners of the records after it",
			content: "www TXT \"x\"\n$ORIGIN sub.example.test.\nwww TXT \"y\"\n",
			records: []string{
				`www.example.test. 300 IN TXT "x"`,
				`www.sub.example.test. 300 IN TXT "y"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err != nil {
				t.Fatalf("parseZoneFile: %v", err)
			}
			if got, want := stringsOf(file.records), rrStrings(t, tt.records...); !slices.Equal(got, want) {
				t.Errorf("records = %q, want %q", got, want)
			}
			if got := file.cuts.sortedCuts(); !slices.Equal(got, tt.cuts) {
				t.Errorf("cuts = %q, want %q", got, tt.cuts)
			}
		})
	}
}

// TestParseZoneFileUnderAnOriginThatCarriesAnAddress checks that the rule on owners that carry an address and the rule on MX and SRV targets look for an address in the labels below the apex only, as queries do.
func TestParseZoneFileUnderAnOriginThatCarriesAnAddress(t *testing.T) {
	const domain = "10-0-0-1.example.test"
	const origin = domain + "."
	server := zoneServer{
		origin:        domain,
		nameServers:   []string{"ns1." + origin, "ns2." + origin},
		challengeName: "_acme-challenge." + origin,
		addresses:     []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.11")},
	}

	tests := []struct {
		name    string
		content string
		records []string
		want    string
	}{
		{
			name:    "a TXT record at a name without an address below the apex is accepted",
			content: "www TXT \"x\"\n",
			records: []string{`www.10-0-0-1.example.test. 300 IN TXT "x"`},
		},
		{
			name:    "an MX record whose target owns an A record is accepted",
			content: "@ MX 10 mail\nmail A 192.0.2.25\n",
			records: []string{"10-0-0-1.example.test. 300 IN MX 10 mail.10-0-0-1.example.test.", "mail.10-0-0-1.example.test. 300 IN A 192.0.2.25"},
		},
		{
			name:    "an MX record whose target is a name of the zone without any record is refused",
			content: "@ MX 10 mial\nmail A 192.0.2.25\n",
			want:    fmt.Sprintf("zone file %s: record %s MX: target mial.%s is inside the zone %s and has no address record", testZoneFileName, origin, origin, origin),
		},
		{
			name:    "a record at a name that carries an address below the apex is refused with that address",
			content: "10-0-0-2 TXT \"x\"\n",
			want:    fmt.Sprintf("zone file %s: record 10-0-0-2.%s TXT: 10-0-0-2.%s carries the address 10.0.0.2 and resolves to it: it cannot have records of its own", testZoneFileName, origin, origin),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, server)
			if tt.want != "" {
				if err == nil {
					t.Fatalf("parseZoneFile succeeded with records %q, want the error %q", stringsOf(file.records), tt.want)
				}
				if err.Error() != tt.want {
					t.Errorf("error = %q\nwant    %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseZoneFile: %v", err)
			}
			if got, want := stringsOf(file.records), rrStrings(t, tt.records...); !slices.Equal(got, want) {
				t.Errorf("records = %q, want %q", got, want)
			}
		})
	}
}

// rdataOf packs a record uncompressed and returns its RDATA octets, which is what the server sends for it whatever the library prints.
func rdataOf(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	buf := make([]byte, dns.Len(rr)+1)
	length, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("packing %s: %v", rr, err)
	}
	ownerLength, err := dns.PackDomainName(rr.Header().Name, make([]byte, maxNameWireLength), 0, nil, false)
	if err != nil {
		t.Fatalf("packing the owner of %s: %v", rr, err)
	}
	return buf[ownerLength+10 : length]
}

// TestParseZoneFilePacksRecordsToTheDeclaredData compares the RDATA octets a stored record packs to, not its presentation, which the library normalises when it prints a record.
func TestParseZoneFilePacksRecordsToTheDeclaredData(t *testing.T) {
	caa := func(tag, value string) []byte {
		return append(append([]byte{0, byte(len(tag))}, tag...), value...)
	}
	tests := []struct {
		name    string
		content string
		rdata   []byte
	}{
		{name: "a CAA value with an escaped backslash packs to the four octets written", content: `www CAA 0 example "\\097"` + "\n", rdata: caa("example", `\097`)},
		{name: "a CAA value with a decimal escape packs to the one octet it stands for", content: `www CAA 0 example "\097"` + "\n", rdata: caa("example", "a")},
		{name: "a TXT string with an escaped backslash packs to the four octets written", content: `www TXT "\\097"` + "\n", rdata: append([]byte{4}, `\097`...)},
		{name: "a TXT string with a decimal escape packs to the one octet it stands for", content: `www TXT "\097"` + "\n", rdata: []byte{1, 'a'}},
		{name: "a CAA record with an empty value packs to its flags and tag alone", content: `www CAA 0 issue ""` + "\n", rdata: []byte("\x00\x05issue")},
		{name: "a CAA tag written in upper case packs as written", content: `@ CAA 0 ISSUE "ca.test"` + "\n", rdata: caa("ISSUE", "ca.test")},
		{name: "an AAAA address in a long spelling packs to the address", content: "www AAAA 2001:0db8:0:0:0:0:0:0001\n", rdata: netip.MustParseAddr("2001:db8::1").AsSlice()},
		{name: "an A address packs to the address", content: "www A 192.0.2.1\n", rdata: []byte{192, 0, 2, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err != nil {
				t.Fatalf("parseZoneFile: %v", err)
			}
			if len(file.records) != 1 {
				t.Fatalf("got %d records, want 1", len(file.records))
			}
			if got := rdataOf(t, file.records[0]); !slices.Equal(got, tt.rdata) {
				t.Errorf("RDATA = %q, want %q", got, tt.rdata)
			}
		})
	}
}

// TestParseZoneFileStoresNamesCanonical looks at the fields of the stored records, which keep the parser's form apart from the names.
func TestParseZoneFileStoresNamesCanonical(t *testing.T) {
	tests := []struct {
		name    string
		content string
		check   func(dns.RR) bool
		want    string
	}{
		{
			name:    "an MX target written with an escape is stored canonical",
			content: `@ MX 10 \077ail.other.test.` + "\n",
			check:   func(rr dns.RR) bool { return rr.(*dns.MX).Mx == "mail.other.test." && rr.(*dns.MX).Preference == 10 },
			want:    "preference 10 and target mail.other.test.",
		},
		{
			name:    "an SRV target is stored canonical with its numbers",
			content: "_sip._tcp SRV 1 2 3 SIP.Other.Test.\n",
			check: func(rr dns.RR) bool {
				srv := rr.(*dns.SRV)
				return srv.Priority == 1 && srv.Weight == 2 && srv.Port == 3 && srv.Target == "sip.other.test."
			},
			want: "1 2 3 sip.other.test.",
		},
		{
			name:    "a CNAME target is stored canonical",
			content: "alias CNAME Target.Other.Test.\n",
			check:   func(rr dns.RR) bool { return rr.(*dns.CNAME).Target == "target.other.test." },
			want:    "target target.other.test.",
		},
		{
			name:    "an owner written with an escape and in upper case is stored canonical",
			content: `\087WW TXT "x"` + "\n",
			check:   func(rr dns.RR) bool { return rr.Header().Name == "www.example.test." },
			want:    "owner www.example.test.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err != nil {
				t.Fatalf("parseZoneFile: %v", err)
			}
			if len(file.records) != 1 {
				t.Fatalf("got %d records, want 1", len(file.records))
			}
			if !tt.check(file.records[0]) {
				t.Errorf("stored record %#v, want %s", file.records[0], tt.want)
			}
		})
	}

	t.Run("an NS record of a delegation is stored canonical", func(t *testing.T) {
		file, err := parseZoneFile(strings.NewReader(`sub NS \078S.Other.Test.`+"\n"), testZoneFileName, testServer)
		if err != nil {
			t.Fatalf("parseZoneFile: %v", err)
		}
		if ns := file.cuts.cuts["sub.example.test."].nameServers; len(ns) != 1 || ns[0].(*dns.NS).Ns != "ns.other.test." {
			t.Errorf("name servers = %q, want the one target ns.other.test.", stringsOf(ns))
		}
	})
}

func TestParseZoneFileRejectsInvalidFiles(t *testing.T) {
	const validDelegation = "sub NS ns1.sub\nns1.sub A 192.0.2.1\n"
	unsupported := "type %s is not supported: the zone file takes NS records for delegations and A, AAAA, CAA, CNAME, MX, SRV and TXT records"

	tests := []struct {
		name    string
		content string
		want    string
		// prefix matches the start of the error only, for messages that end with the library's own words.
		prefix bool
	}{
		{
			name:    "class other than IN",
			content: "sub CH NS ns.other.test.\n",
			want:    recordFault("sub.example.test.", "NS", "class CH is not supported, only IN"),
		},
		{
			name:    "PTR record",
			content: "www PTR other.test.\n",
			want:    recordFault("www.example.test.", "PTR", fmt.Sprintf(unsupported, "PTR")),
		},
		{
			name:    "SOA record at the apex",
			content: "@ SOA ns1 admin 1 900 900 1800 300\n",
			want:    recordFault("example.test.", "SOA", fmt.Sprintf(unsupported, "SOA")),
		},
		{
			name:    "DNAME record",
			content: "www DNAME other.test.\n",
			want:    recordFault("www.example.test.", "DNAME", fmt.Sprintf(unsupported, "DNAME")),
		},
		{
			name:    "HTTPS record",
			content: "www HTTPS 1 . alpn=h2\n",
			want:    recordFault("www.example.test.", "HTTPS", fmt.Sprintf(unsupported, "HTTPS")),
		},
		{
			name:    "record of an unassigned type",
			content: `www TYPE65280 \# 1 00` + "\n",
			want:    recordFault("www.example.test.", "TYPE65280", fmt.Sprintf(unsupported, "TYPE65280")),
		},
		{
			name:    "a CAA record whose tag is longer than 255 octets cannot be encoded",
			content: "www CAA 0 " + strings.Repeat("x", 256) + " \"v\"\n",
			want:    recordFault("www.example.test.", "CAA", "cannot be encoded: "),
			prefix:  true,
		},
		{
			name:    "a TXT record of more than 65535 octets of data cannot be encoded",
			content: "www TXT \"" + strings.Repeat("x", 65280) + "\"\n",
			want:    recordFault("www.example.test.", "TXT", "cannot be encoded: "),
			prefix:  true,
		},
		{
			name:    "TXT record of exactly 65535 octets of data outside the zone",
			content: "www.other.test. TXT \"" + strings.Repeat("x", 65279) + "\"\n",
			want:    recordFault("www.other.test.", "TXT", "owner is outside the zone example.test."),
		},
		{
			name:    "TXT record of exactly 65535 octets of data inside the zone has too large an answer",
			content: "big TXT \"" + strings.Repeat("x", 65279) + "\"\n",
			want:    "zone file test.zone: the answer for big.example.test. TXT takes 65581 octets, more than the limit of 65524 octets for a DNS message",
		},
		{
			name:    "NS record outside the zone",
			content: "sub.other.test. NS ns.other.test.\n",
			want:    recordFault("sub.other.test.", "NS", "owner is outside the zone example.test."),
		},
		{
			name:    "TXT record outside the zone",
			content: "www.other.test. TXT \"x\"\n",
			want:    recordFault("www.other.test.", "TXT", "owner is outside the zone example.test."),
		},
		{
			name:    "a record after an $ORIGIN outside the zone",
			content: "$ORIGIN other.test.\nwww TXT \"x\"\n",
			want:    recordFault("www.other.test.", "TXT", "owner is outside the zone example.test."),
		},
		{
			name:    "NS record at the apex",
			content: "@ NS ns.other.test.\n",
			want:    recordFault("example.test.", "NS", "an NS record must be below the apex example.test.: the zone's own name servers come from the configuration"),
		},
		{
			name:    "wildcard owner",
			content: "*.sub NS ns.other.test.\n",
			want:    recordFault("*.sub.example.test.", "NS", "wildcard owners are not supported"),
		},
		{
			name:    "wildcard label spelled with a decimal escape",
			content: `\042.sub NS ns.other.test.` + "\n",
			want:    recordFault("*.sub.example.test.", "NS", "wildcard owners are not supported"),
		},
		{
			name:    "wildcard TXT record",
			content: "*.www TXT \"x\"\n",
			want:    recordFault("*.www.example.test.", "TXT", "wildcard owners are not supported"),
		},
		{
			name:    "duplicate glue record",
			content: validDelegation + "ns1.sub A 192.0.2.1\n",
			want:    recordFault("ns1.sub.example.test.", "A", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate record differing only in case and TTL",
			content: "sub NS ns.other.test.\nSUB 600 NS NS.OTHER.TEST.\n",
			want:    recordFault("sub.example.test.", "NS", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate record spelled with a decimal escape",
			content: "sub NS ns.other.test.\n" + `\115ub NS ns.other.test.` + "\n",
			want:    recordFault("sub.example.test.", "NS", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate MX record whose targets differ in case",
			content: "@ MX 10 mail.other.test.\n@ MX 10 MAIL.other.test.\n",
			want:    recordFault("example.test.", "MX", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate TXT record whose string is written with a decimal escape",
			content: "www TXT \"a\"\n" + `www TXT "\097"` + "\n",
			want:    recordFault("www.example.test.", "TXT", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate CAA record whose value is written with a decimal escape",
			content: "www CAA 0 issue \"a\"\n" + `www CAA 0 issue "\097"` + "\n",
			want:    recordFault("www.example.test.", "CAA", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate written with an escape and another TTL is reported as a duplicate, not as a TTL mismatch",
			content: "www TXT \"a\"\n" + `www 60 TXT "\097"` + "\n",
			want:    recordFault("www.example.test.", "TXT", "duplicate of an earlier record"),
		},
		{
			name:    "duplicate AAAA record written in two spellings",
			content: "www AAAA 2001:db8::1\nwww AAAA 2001:0db8:0:0:0:0:0:0001\n",
			want:    recordFault("www.example.test.", "AAAA", "duplicate of an earlier record"),
		},
		{
			name:    "SRV record whose target is a name of the zone without any record",
			content: "_sip._tcp SRV 0 5 5060 missing\n",
			want:    recordFault("_sip._tcp.example.test.", "SRV", "target missing.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "NS records of one set with different TTLs",
			content: "sub 300 NS a.other.test.\nsub 600 NS b.other.test.\n",
			want:    recordFault("sub.example.test.", "NS", "TTL 600 differs from TTL 300 of an earlier record with the same owner and type"),
		},
		{
			name:    "TXT records of one set with different TTLs",
			content: "www 300 TXT \"a\"\nwww 60 TXT \"b\"\n",
			want:    recordFault("www.example.test.", "TXT", "TTL 60 differs from TTL 300 of an earlier record with the same owner and type"),
		},
		{
			name:    "cut below another cut",
			content: "sub NS ns.other.test.\na.sub NS ns.other.test.\n",
			want:    recordFault("a.sub.example.test.", "NS", "delegation is nested below the delegation sub.example.test."),
		},
		{
			name:    "cut below another cut declared first",
			content: "a.sub NS ns.other.test.\nsub NS ns.other.test.\n",
			want:    recordFault("a.sub.example.test.", "NS", "delegation is nested below the delegation sub.example.test."),
		},
		{
			name:    "cut below another cut spelled with a decimal escape",
			content: "sub NS ns.other.test.\n" + `a.\115ub NS ns.other.test.` + "\n",
			want:    recordFault("a.sub.example.test.", "NS", "delegation is nested below the delegation sub.example.test."),
		},
		{
			name:    "cut spelled with decimal escapes equal to a name server of the server",
			content: `\110\115\049 NS ns.other.test.` + "\n",
			want:    recordFault("ns1.example.test.", "NS", "ns1.example.test. is reserved and cannot be delegated"),
		},
		{
			name:    "cut equal to a name server of the server",
			content: "ns1 NS ns.other.test.\n",
			want:    recordFault("ns1.example.test.", "NS", "ns1.example.test. is reserved and cannot be delegated"),
		},
		{
			name:    "cut equal to a name server the server is given in non-canonical form",
			content: "ns2 NS ns.other.test.\n",
			want:    recordFault("ns2.example.test.", "NS", "ns2.example.test. is reserved and cannot be delegated"),
		},
		{
			name:    "cut equal to the ACME challenge name, which the server is given with a decimal escape",
			content: "_acme-challenge NS ns.other.test.\n",
			want:    recordFault("_acme-challenge.example.test.", "NS", "_acme-challenge.example.test. is reserved and cannot be delegated"),
		},
		{
			name:    "name server elsewhere inside the zone",
			content: "sub NS ns.other\nns.other A 192.0.2.1\n",
			want:    recordFault("sub.example.test.", "NS", "name server ns.other.example.test. is inside the zone example.test. but outside the delegated zone sub.example.test.; it must be inside the delegated zone (with glue) or outside the zone"),
		},
		{
			name:    "name server spelled with a decimal escape is one of the server's own name servers",
			content: `sub NS ns1.\101xample.test.` + "\n",
			want:    recordFault("sub.example.test.", "NS", "name server ns1.example.test. is inside the zone example.test. but outside the delegated zone sub.example.test.; it must be inside the delegated zone (with glue) or outside the zone"),
		},
		{
			name:    "name server is the apex",
			content: "sub NS @\n",
			want:    recordFault("sub.example.test.", "NS", "name server example.test. is inside the zone example.test. but outside the delegated zone sub.example.test.; it must be inside the delegated zone (with glue) or outside the zone"),
		},
		{
			name:    "two cuts whose name servers sit inside each other",
			content: "one NS ns.two\ntwo NS ns.one\nns.one A 192.0.2.1\nns.two A 192.0.2.2\n",
			want:    recordFault("one.example.test.", "NS", "name server ns.two.example.test. is inside the zone example.test. but outside the delegated zone one.example.test.; it must be inside the delegated zone (with glue) or outside the zone"),
		},
		{
			name:    "in-cut name server without glue",
			content: "sub NS ns1.sub\n",
			want:    recordFault("sub.example.test.", "NS", "name server ns1.sub.example.test. is inside the delegated zone and has no A or AAAA glue record"),
		},
		{
			name:    "address record inside a cut that is not a name server",
			content: validDelegation + "www.sub AAAA 2001:db8::2\n",
			want:    recordFault("www.sub.example.test.", "AAAA", "address record is not glue: www.sub.example.test. is not a name server of the delegation sub.example.test."),
		},
		{
			name:    "A glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub A 198.51.100.10\n",
			want:    recordFault("ns1.sub.example.test.", "A", "name server ns1.sub.example.test. has the address 198.51.100.10, which is one of this server's own name server addresses; the delegation would point back at this server"),
		},
		{
			name:    "AAAA glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub AAAA 2001:db8:ffff::10\n",
			want:    recordFault("ns1.sub.example.test.", "AAAA", "name server ns1.sub.example.test. has the address 2001:db8:ffff::10, which is one of this server's own name server addresses; the delegation would point back at this server"),
		},
		{
			name:    "IPv4-mapped AAAA glue equal to one of the server's own addresses",
			content: "sub NS ns1.sub\nns1.sub AAAA ::ffff:198.51.100.10\n",
			want:    recordFault("ns1.sub.example.test.", "AAAA", "name server ns1.sub.example.test. has the address 198.51.100.10, which is one of this server's own name server addresses; the delegation would point back at this server"),
		},
		{
			name:    "TXT record at a cut",
			content: validDelegation + "sub TXT \"x\"\n",
			want:    recordFault("sub.example.test.", "TXT", "sub.example.test. is at or below the delegation sub.example.test., where this server answers with a referral: only the addresses of its name servers can be declared there"),
		},
		{
			name:    "MX record below a cut",
			content: validDelegation + "mail.sub MX 10 mail.other.test.\n",
			want:    recordFault("mail.sub.example.test.", "MX", "mail.sub.example.test. is at or below the delegation sub.example.test., where this server answers with a referral: only the addresses of its name servers can be declared there"),
		},
		{
			name:    "TXT record at a name server of the server",
			content: "ns1 TXT \"x\"\n",
			want:    recordFault("ns1.example.test.", "TXT", "ns1.example.test. is reserved: the server answers for it itself"),
		},
		{
			name:    "A record at a name server of the server",
			content: "ns2 A 192.0.2.2\n",
			want:    recordFault("ns2.example.test.", "A", "ns2.example.test. is reserved: the server answers for it itself"),
		},
		{
			name:    "TXT record at the ACME challenge name",
			content: "_acme-challenge TXT \"x\"\n",
			want:    recordFault("_acme-challenge.example.test.", "TXT", "_acme-challenge.example.test. is reserved: the server answers for it itself"),
		},
		{
			name:    "A record at the apex",
			content: "@ A 192.0.2.1\n",
			want:    recordFault("example.test.", "A", "the A records of the apex are the configured name server addresses"),
		},
		{
			name:    "CNAME record at the apex",
			content: "@ CNAME target.other.test.\n",
			want:    recordFault("example.test.", "CNAME", "a CNAME record cannot be at the apex"),
		},
		{
			name:    "TXT record at a dashed address",
			content: "10-0-0-1 TXT \"x\"\n",
			want:    recordFault("10-0-0-1.example.test.", "TXT", "10-0-0-1.example.test. carries the address 10.0.0.1 and resolves to it: it cannot have records of its own"),
		},
		{
			name:    "TXT record at a dashed address after a name in its label",
			content: "app-10-0-0-1 TXT \"x\"\n",
			want:    recordFault("app-10-0-0-1.example.test.", "TXT", "app-10-0-0-1.example.test. carries the address 10.0.0.1 and resolves to it: it cannot have records of its own"),
		},
		{
			name:    "A record below a dashed address",
			content: "app.10-0-0-1 A 192.0.2.1\n",
			want:    recordFault("app.10-0-0-1.example.test.", "A", "app.10-0-0-1.example.test. carries the address 10.0.0.1 and resolves to it: it cannot have records of its own"),
		},
		{
			name:    "MX record above a dotted address",
			content: "10.0.0.1.app MX 10 mail.other.test.\n",
			want:    recordFault("10.0.0.1.app.example.test.", "MX", "10.0.0.1.app.example.test. carries the address 10.0.0.1 and resolves to it: it cannot have records of its own"),
		},
		{
			name:    "CNAME record before a TXT record at one name",
			content: "www CNAME target.other.test.\nwww TXT \"x\"\n",
			want:    recordFault("www.example.test.", "CNAME", "www.example.test. has a CNAME record and other records: a CNAME must be alone at its name"),
		},
		{
			name:    "TXT record before a CNAME record at one name",
			content: "www TXT \"x\"\nwww CNAME target.other.test.\n",
			want:    recordFault("www.example.test.", "TXT", "www.example.test. has a CNAME record and other records: a CNAME must be alone at its name"),
		},
		{
			name:    "two CNAME records at one name",
			content: "www CNAME a.other.test.\nwww CNAME b.other.test.\n",
			want:    recordFault("www.example.test.", "CNAME", "www.example.test. has more than one CNAME record"),
		},
		{
			name:    "CNAME target at the apex",
			content: "alias CNAME @\n",
			want:    recordFault("alias.example.test.", "CNAME", "CNAME target example.test. is inside the zone example.test.: only targets outside the zone are supported"),
		},
		{
			name:    "CNAME target below the apex",
			content: "alias CNAME www\nwww A 192.0.2.80\n",
			want:    recordFault("alias.example.test.", "CNAME", "CNAME target www.example.test. is inside the zone example.test.: only targets outside the zone are supported"),
		},
		{
			name:    "CNAME target inside a cut",
			content: "alias CNAME www.sub\nsub NS ns.other.test.\n",
			want:    recordFault("alias.example.test.", "CNAME", "CNAME target www.sub.example.test. is inside the zone example.test.: only targets outside the zone are supported"),
		},
		{
			name:    "MX record whose target owns a CNAME record",
			content: "@ MX 10 alias\nalias CNAME target.other.test.\n",
			want:    recordFault("example.test.", "MX", "target alias.example.test. is an alias: the target of an MX or SRV record must not own a CNAME record"),
		},
		{
			name:    "SRV record whose target owns a CNAME record",
			content: "_sip._tcp SRV 0 5 5060 alias\nalias CNAME target.other.test.\n",
			want:    recordFault("_sip._tcp.example.test.", "SRV", "target alias.example.test. is an alias: the target of an MX or SRV record must not own a CNAME record"),
		},
		{
			name:    "MX record whose target is a name of the zone without any record",
			content: "@ MX 10 mial\nmail A 192.0.2.25\n",
			want:    recordFault("example.test.", "MX", "target mial.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "MX record whose target is an empty non-terminal",
			content: "@ MX 10 er.name\ndeep.er.name A 192.0.2.25\n",
			want:    recordFault("example.test.", "MX", "target er.name.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "MX record whose target owns only a TXT record",
			content: "@ MX 10 mail\nmail TXT \"x\"\n",
			want:    recordFault("example.test.", "MX", "target mail.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "MX record whose target is the ACME challenge name",
			content: "@ MX 10 _acme-challenge\n",
			want:    recordFault("example.test.", "MX", "target _acme-challenge.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "referral larger than a DNS message",
			content: manyNameServers(oversizedNameServerCount),
			want:    fmt.Sprintf("zone file test.zone: delegation sub.example.test.: the largest referral takes %d octets, more than the limit of 65524 octets for a DNS message", manyNameServersReferralSize(t, oversizedNameServerCount)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prefix {
				expectZoneFileErrorPrefix(t, tt.content, tt.want)
				return
			}
			expectZoneFileError(t, tt.content, tt.want)
		})
	}
}

func expectZoneFileError(t *testing.T, content, want string) {
	t.Helper()
	if err := zoneFileError(t, content); err.Error() != want {
		t.Errorf("error = %q\nwant    %q", err, want)
	}
}

func expectZoneFileErrorPrefix(t *testing.T, content, prefix string) {
	t.Helper()
	if err := zoneFileError(t, content); !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %q\nwant it to start with %q", err, prefix)
	}
}

func zoneFileError(t *testing.T, content string) error {
	t.Helper()
	got, err := parseZoneFile(strings.NewReader(content), testZoneFileName, testServer)
	if err == nil {
		t.Fatalf("parseZoneFile succeeded with cuts %v and records %q, want an error", got.cuts.sortedCuts(), stringsOf(got.records))
	}
	if got != nil {
		t.Errorf("parseZoneFile returned %v together with an error", got)
	}
	return err
}

func TestParseZoneFileRejectsRecordsWithoutData(t *testing.T) {
	tests := []struct {
		name    string
		content string
		owner   string
		rrtype  string
	}{
		{name: "an NS record without a target as the last line", content: "sub NS\n", owner: "sub.example.test.", rrtype: "NS"},
		{name: "an A record without an address as the last line", content: "sub NS ns1.sub\nns1.sub A\n", owner: "ns1.sub.example.test.", rrtype: "A"},
		{name: "an AAAA record without an address as the last line", content: "sub NS ns1.sub\nns1.sub AAAA\n", owner: "ns1.sub.example.test.", rrtype: "AAAA"},
		{name: "a CNAME record without a target as the last line", content: "alias CNAME\n", owner: "alias.example.test.", rrtype: "CNAME"},
		{name: "an MX record without data as the last line", content: "@ MX\n", owner: "example.test.", rrtype: "MX"},
		{name: "an SRV record without data as the last line", content: "_sip._tcp SRV\n", owner: "_sip._tcp.example.test.", rrtype: "SRV"},
		{name: "a TXT record without a string as the last line", content: "www TXT\n", owner: "www.example.test.", rrtype: "TXT"},
		{name: "a CAA record without data as the last line", content: "@ CAA\n", owner: "example.test.", rrtype: "CAA"},
		{name: "a TXT record of zero octets before another record", content: `www TXT \# 0` + "\nother TXT \"x\"\n", owner: "www.example.test.", rrtype: "TXT"},
		{name: "an MX record of zero octets before another record", content: `@ MX \# 0` + "\nother TXT \"x\"\n", owner: "example.test.", rrtype: "MX"},
		{name: "a CNAME record of zero octets", content: `alias CNAME \# 0` + "\n", owner: "alias.example.test.", rrtype: "CNAME"},
		{name: "an SRV record of zero octets", content: `_sip._tcp SRV \# 0` + "\n", owner: "_sip._tcp.example.test.", rrtype: "SRV"},
		{name: "a CAA record of zero octets", content: `@ CAA \# 0` + "\n", owner: "example.test.", rrtype: "CAA"},
		{name: "an A record of zero octets", content: `www A \# 0` + "\n", owner: "www.example.test.", rrtype: "A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectZoneFileError(t, tt.content, recordFault(tt.owner, tt.rrtype, "record has no data"))
		})
	}
}

func TestParseZoneFileRejectsUnparsableFiles(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{name: "syntax error", content: "sub NS ns1.sub\nns1.sub A not-an-address\n", want: []string{"parsing zone file", "not-an-address"}},
		{name: "$INCLUDE directive", content: "$INCLUDE other.zone\n", want: []string{"parsing zone file", "$INCLUDE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseZoneFile(strings.NewReader(tt.content), testZoneFileName, testServer)
			if err == nil {
				t.Fatalf("parseZoneFile succeeded with %v, want an error", got)
			}
			for _, want := range append([]string{testZoneFileName}, tt.want...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestParseZoneFileRefusesGenerate(t *testing.T) {
	tests := []struct {
		name    string
		content string
		line    int
	}{
		{name: "in upper case", content: "www TXT \"x\"\n$GENERATE 1-3 host$ A 192.0.2.$\n", line: 2},
		{name: "in lower case", content: "www TXT \"x\"\n\nwww TXT \"y\"\n$generate 1-3 host$ A 192.0.2.$\n", line: 4},
		{name: "followed by a tab", content: "$GENERATE\t1-3 host$ A 192.0.2.$\n", line: 1},
		{name: "in a file with CRLF line endings", content: "www TXT \"x\"\r\n$GENERATE 1-3 host$ A 192.0.2.$\r\n", line: 2},
		{name: "as the continuation line of a record in parentheses", content: "www TXT ( \"x\"\n$GENERATE \"y\" )\n", line: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectZoneFileError(t, tt.content, fmt.Sprintf("zone file %s: line %d: $GENERATE is not supported", testZoneFileName, tt.line))
		})
	}
}

// TestParseZoneFileReportsFaultsInOrder gives files with two faults each and expects the one the order of the checks names, whatever the order of the records in the file.
func TestParseZoneFileReportsFaultsInOrder(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "an unsupported type comes before a nested delegation declared earlier",
			content: "sub NS ns.other.test.\na.sub NS ns.other.test.\nwww PTR other.test.\n",
			want:    recordFault("www.example.test.", "PTR", "type PTR is not supported: the zone file takes NS records for delegations and A, AAAA, CAA, CNAME, MX, SRV and TXT records"),
		},
		{
			name:    "TTLs that differ within a record set come before a record at a reserved name declared earlier",
			content: "ns1 TXT \"x\"\nwww 300 TXT \"a\"\nwww 600 TXT \"b\"\n",
			want:    recordFault("www.example.test.", "TXT", "TTL 600 differs from TTL 300 of an earlier record with the same owner and type"),
		},
		{
			name:    "a name server without glue comes before a record below a cut declared earlier",
			content: "www.sub TXT \"x\"\nsub NS ns1.sub\n",
			want:    recordFault("sub.example.test.", "NS", "name server ns1.sub.example.test. is inside the delegated zone and has no A or AAAA glue record"),
		},
		{
			name:    "a CNAME target inside the zone comes before an MX target without an address declared earlier",
			content: "@ MX 10 mial\nalias CNAME www\nwww A 192.0.2.80\n",
			want:    recordFault("alias.example.test.", "CNAME", "CNAME target www.example.test. is inside the zone example.test.: only targets outside the zone are supported"),
		},
		{
			name:    "an MX target without an address comes before an answer too large declared earlier",
			content: "big TXT \"" + strings.Repeat("x", 65279) + "\"\n@ MX 10 mial\n",
			want:    recordFault("example.test.", "MX", "target mial.example.test. is inside the zone example.test. and has no address record"),
		},
		{
			name:    "the size of a record set comes before the size of a referral declared earlier",
			content: manyNameServers(oversizedNameServerCount) + "big TXT \"" + strings.Repeat("x", 65279) + "\"\n",
			want:    "zone file test.zone: the answer for big.example.test. TXT takes 65581 octets, more than the limit of 65524 octets for a DNS message",
		},
		{
			name:    "one record is checked for an owner that carries an address before the CNAME rules",
			content: "10-0-0-1 CNAME target.other.test.\n10-0-0-1 TXT \"x\"\n",
			want:    recordFault("10-0-0-1.example.test.", "CNAME", "10-0-0-1.example.test. carries the address 10.0.0.1 and resolves to it: it cannot have records of its own"),
		},
		{
			name:    "one record is checked for an owner below a cut before the other rules on records",
			content: "sub NS ns.other.test.\nalias.sub CNAME www\n",
			want:    recordFault("alias.sub.example.test.", "CNAME", "alias.sub.example.test. is at or below the delegation sub.example.test., where this server answers with a referral: only the addresses of its name servers can be declared there"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectZoneFileError(t, tt.content, tt.want)
		})
	}

	t.Run("a record that cannot be encoded is reported as such before an owner outside the zone", func(t *testing.T) {
		expectZoneFileErrorPrefix(t, "www.other.test. CAA 0 "+strings.Repeat("x", 256)+" \"v\"\n", recordFault("www.other.test.", "CAA", "cannot be encoded: "))
	})
}

// answerSizeOf packs an answer the way the server sends it, independently of parseZoneFile, so the size tests do not trust the code under test to measure: the question for owner in ASCII upper case and the records owned by that name.
func answerSizeOf(t *testing.T, owner string, records ...string) int {
	t.Helper()
	return answerSizeFor(t, strings.ToUpper(owner), records...)
}

// answerSizeFor packs the answer to a question for qname spelled exactly as given, with the records owned by that spelling.
func answerSizeFor(t *testing.T, qname string, records ...string) int {
	t.Helper()
	msg := new(dns.Msg)
	msg.Compress = true
	for _, record := range records {
		rr := mustRR(t, record)
		rr.Header().Name = qname
		msg.Answer = append(msg.Answer, rr)
	}
	msg.SetQuestion(qname, msg.Answer[0].Header().Rrtype)
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("packing the answer for %s: %v", qname, err)
	}
	return len(packed)
}

// largestFittingTXTLength is the length of the one string of a TXT record at big.example.test. whose answer takes 65524 octets, the most that fits in a DNS message with the server's OPT record of 11 octets.
const largestFittingTXTLength = 65222

func TestParseZoneFileAnswerSizeBoundary(t *testing.T) {
	const owner = "big.example.test."
	txt := func(length int) string { return strings.Repeat("x", length) }
	sizeOf := func(length int) int {
		zp := dns.NewZoneParser(strings.NewReader(fmt.Sprintf("%s 300 IN TXT \"%s\"\n", owner, txt(length))), "", "")
		rr, ok := zp.Next()
		if !ok {
			t.Fatalf("parsing a TXT record of %d octets: %v", length, zp.Err())
		}
		return answerSizeOf(t, owner, rr.String())
	}
	if got := sizeOf(largestFittingTXTLength); got != maxReplyWithoutOPT {
		t.Fatalf("a TXT string of %d octets makes an answer of %d octets, want exactly %d", largestFittingTXTLength, got, maxReplyWithoutOPT)
	}
	if got := sizeOf(largestFittingTXTLength + 1); got != maxReplyWithoutOPT+1 {
		t.Fatalf("one octet more makes an answer of %d octets, want %d", got, maxReplyWithoutOPT+1)
	}

	t.Run("a TXT record set whose answer takes 65524 octets is accepted", func(t *testing.T) {
		if _, err := parseZoneFile(strings.NewReader(fmt.Sprintf("big TXT \"%s\"\n", txt(largestFittingTXTLength))), testZoneFileName, testServer); err != nil {
			t.Fatalf("parseZoneFile: %v", err)
		}
	})
	t.Run("a TXT record set whose answer takes 65525 octets is refused", func(t *testing.T) {
		expectZoneFileError(t, fmt.Sprintf("big TXT \"%s\"\n", txt(largestFittingTXTLength+1)), "zone file test.zone: the answer for big.example.test. TXT takes 65525 octets, more than the limit of 65524 octets for a DNS message")
	})
	t.Run("the records of one set are measured together", func(t *testing.T) {
		half := largestFittingTXTLength / 2
		first, second := txt(half), strings.Repeat("y", half)
		size := answerSizeOf(t, owner, fmt.Sprintf("%s 300 IN TXT %q", owner, first), fmt.Sprintf("%s 300 IN TXT %q", owner, second))
		if size <= maxReplyWithoutOPT {
			t.Fatalf("two TXT records of %d octets make an answer of %d octets, want more than %d", half, size, maxReplyWithoutOPT)
		}
		content := fmt.Sprintf("big TXT \"%s\"\nbig TXT \"%s\"\n", first, second)
		expectZoneFileError(t, content, fmt.Sprintf("zone file test.zone: the answer for big.example.test. TXT takes %d octets, more than the limit of 65524 octets for a DNS message", size))
	})
}

// TestParseZoneFileMeasuresAnswersForAnUpperCaseQuestion uses an MX set whose targets are below its owner: a lower-case question lets every target compress against it, so the set fits for that question and not for the upper-case one, which the loader must measure.
func TestParseZoneFileMeasuresAnswersForAnUpperCaseQuestion(t *testing.T) {
	label := strings.Repeat("m", maxLabelLength)
	owner := label + ".example.test."
	target := func(i int) string { return fmt.Sprintf("10-0-%d-%d.%s", i/256, i%256, owner) }
	setOf := func(count int) []string {
		records := make([]string, count)
		for i := range count {
			records[i] = fmt.Sprintf("%s 300 IN MX 10 %s", owner, target(i))
		}
		return records
	}

	// The smallest set too large for an upper-case question, found by bisection since the sets are large.
	low, high := 1, 4096
	if answerSizeOf(t, owner, setOf(high)...) <= maxReplyWithoutOPT {
		t.Fatalf("%d MX records fit: choose more", high)
	}
	for low < high {
		mid := (low + high) / 2
		if answerSizeOf(t, owner, setOf(mid)...) > maxReplyWithoutOPT {
			high = mid
		} else {
			low = mid + 1
		}
	}
	count := low
	upperSize := answerSizeOf(t, owner, setOf(count)...)
	if lowerSize := answerSizeFor(t, owner, setOf(count)...); lowerSize > maxReplyWithoutOPT {
		t.Fatalf("%d MX records make an answer of %d octets for a lower-case question, which does not fit either: choose another owner", count, lowerSize)
	}

	var content strings.Builder
	for i := range count {
		fmt.Fprintf(&content, "%s MX 10 %s\n", label, target(i))
	}
	expectZoneFileError(t, content.String(), fmt.Sprintf("zone file test.zone: the answer for %s MX takes %d octets, more than the limit of 65524 octets for a DNS message", owner, upperSize))
}

// oversizedNameServerCount is a number of in-cut name servers whose referral does not fit in a DNS message.
const oversizedNameServerCount = 2000

func manyNameServers(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "sub NS ns%d.sub\nns%d.sub A %s\n", i, i, manyNameServersAddress(i))
	}
	return b.String()
}

// manyNameServersAddress is the address of the i-th name server of manyNameServers, a different one for each.
func manyNameServersAddress(i int) string {
	return fmt.Sprintf("10.0.%d.%d", i/256, i%256)
}

// referralProbe is the longest name inside sub.example.test. in upper case, written out so that the referral tests do not take the probe from the code under test.
var referralProbe = strings.ToUpper(strings.Repeat("x", 63) + "." + strings.Repeat("x", 63) + "." + strings.Repeat("x", 63) + "." + strings.Repeat("x", 44) + ".sub.example.test.")

// referralSizeOf packs the referral of a delegation of sub.example.test. for the probe name, independently of parseZoneFile, so the size tests do not trust the code under test to measure.
func referralSizeOf(t *testing.T, nameServers, glue []string) int {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(referralProbe, dns.TypeA)
	msg.Compress = true
	for _, record := range nameServers {
		msg.Ns = append(msg.Ns, mustRR(t, record))
	}
	for _, record := range glue {
		msg.Extra = append(msg.Extra, mustRR(t, record))
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("packing referral: %v", err)
	}
	return len(packed)
}

// manyNameServersReferralSize is the size of the referral for the delegation manyNameServers(n) declares.
func manyNameServersReferralSize(t *testing.T, n int) int {
	t.Helper()
	var nameServers, glue []string
	for i := range n {
		nameServers = append(nameServers, fmt.Sprintf("sub.example.test. 300 IN NS ns%d.sub.example.test.", i))
		glue = append(glue, fmt.Sprintf("ns%d.sub.example.test. 300 IN A %s", i, manyNameServersAddress(i)))
	}
	return referralSizeOf(t, nameServers, glue)
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
	for _, cut := range []string{"sub.example.test.", "a.b.c.example.test.", "xip-staging.local-ip.sh.", "x.example.test."} {
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
		file, err := parseZoneFile(strings.NewReader(content), testZoneFileName, testServer)
		if err != nil {
			t.Fatal(err)
		}
		return file.cuts
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
		{name: "a canonical name two labels below", zc: staging, query: "www.app.staging.example.test.", wantCut: "staging.example.test."},
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

// A delegation takes every name below its label away from the hosted instance, including names
// that carry an address, so the hosted instance only delegates labels reserved for the project.
const projectLabelPrefix = "xip-"

func isProjectCut(cut, origin string) bool {
	origin = dns.Fqdn(origin)
	if !dns.IsSubDomain(origin, cut) {
		return false
	}
	labels := dns.SplitDomainName(cut)
	below := len(labels) - dns.CountLabel(origin)
	if below < 1 {
		return false
	}
	return strings.HasPrefix(labels[below-1], projectLabelPrefix)
}

func TestIsProjectCut(t *testing.T) {
	tests := []struct {
		cut  string
		want bool
	}{
		{cut: "xip-staging.local-ip.sh.", want: true},
		{cut: "dev.local-ip.sh.", want: false},
		{cut: "xipstaging.local-ip.sh.", want: false},
		{cut: "staging.xip.local-ip.sh.", want: false},
		{cut: "a.xip-staging.local-ip.sh.", want: true},
		{cut: "xip-staging.example.test.", want: false},
		{cut: "local-ip.sh.", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.cut, func(t *testing.T) {
			if got := isProjectCut(tt.cut, "local-ip.sh"); got != tt.want {
				t.Errorf("isProjectCut(%q, %q) = %v, want %v", tt.cut, "local-ip.sh", got, tt.want)
			}
		})
	}
}

// hostedRSADKIMValue is the RSA DKIM key that mail.mial.net signs the domain's mail with.
const hostedRSADKIMValue = "v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2y9b1q/Of6doBMq4f16YJkM9BSMAdiNCyQhy1BcEVG9XpIObaJzhRWddhAPB6Awz/QqnCkx51AXuMDgKIsv2Cs87+jJoILdJ2T6HhS05kZj5FHBKMNctgcFzN2XRhXXpIVLWbA9Ef7takTa2AO5+qCT0M1xkumNQEXc/znTuaWS86e766hLA06a7pBwriJj4ceb5V6/q5fvfVq+EgJnk8WQ9DQRs4VjHaSVN0fscRzzJsZAQpa6KqmSLiXzM+NktGN40EZGqFrvvGcfdE+jEa++rePixXgKsETZCR32tKCNCELzbdTGchu01F6vZVxT/AGNfxzFWs9tuXdiltYmhbwIDAQAB"

// rigTXTRecords spells a TXT set the e2e rig's zone file declares for the suite's truncation cases: n records, each of one string of 180 octets that starts with its position.
func rigTXTRecords(label string, n int) []string {
	records := make([]string, n)
	for i := range n {
		prefix := fmt.Sprintf("%s record %d of %d ", label, i+1, n)
		records[i] = fmt.Sprintf(`%s.local-ip.test. 300 IN TXT "%s%s"`, label, prefix, strings.Repeat("x", 180-len(prefix)))
	}
	return records
}

// recordSetCount counts the distinct owner and type pairs among records.
func recordSetCount(records []dns.RR) int {
	type setKey struct {
		owner  string
		rrtype uint16
	}
	sets := make(map[setKey]bool)
	for _, rr := range records {
		sets[setKey{rr.Header().Name, rr.Header().Rrtype}] = true
	}
	return len(sets)
}

// TestRepositoryZoneFiles loads the zone files of the repository the way the servers they are delivered to do, so a file that would stop a server at startup fails here first.
func TestRepositoryZoneFiles(t *testing.T) {
	tests := []struct {
		path          string
		origin        string
		nameServers   []string
		challengeName string
		addresses     []netip.Addr
		cuts          []string
		records       []string
		recordSets    int
		// The hosted instance has users whose names a delegation would take away; the e2e rig has none.
		hosted bool
	}{
		{
			path:          filepath.Join("..", "zones", "local-ip.sh.zone"),
			origin:        "local-ip.sh",
			nameServers:   []string{"ns1.local-ip.sh.", "ns2.local-ip.sh."},
			challengeName: "_acme-challenge.local-ip.sh.",
			addresses:     []netip.Addr{netip.MustParseAddr("137.66.40.11"), netip.MustParseAddr("137.66.40.12")},
			cuts:          nil,
			records: []string{
				"local-ip.sh. 300 IN MX 10 mail.mial.net.",
				`local-ip.sh. 300 IN TXT "v=spf1 mx -all"`,
				`202411e._domainkey.local-ip.sh. 300 IN TXT "v=DKIM1; k=ed25519; h=sha256; p=Xic3wKt0G+05OJw4q9U5FImcGnvKcMK5chBgYljJv8c="`,
				fmt.Sprintf(`202411r._domainkey.local-ip.sh. 300 IN TXT "%s" "%s"`, hostedRSADKIMValue[:255], hostedRSADKIMValue[255:]),
				`_dmarc.local-ip.sh. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@local-ip.sh"`,
				`_smtp._tls.local-ip.sh. 300 IN TXT "v=TLSRPTv1; rua=mailto:postmaster@local-ip.sh"`,
			},
			recordSets: 6,
			hosted:     true,
		},
		{
			path:          filepath.Join("..", "e2e", "rig", "zone"),
			origin:        "local-ip.test",
			nameServers:   []string{"ns1.local-ip.test."},
			challengeName: "_acme-challenge.local-ip.test.",
			addresses:     []netip.Addr{netip.MustParseAddr("10.253.53.53")},
			cuts:          []string{"e2e-delegated.local-ip.test."},
			records: append([]string{
				"e2e-records.local-ip.test. 300 IN A 192.0.2.10",
				"e2e-records.local-ip.test. 300 IN AAAA 2001:db8::10",
				`e2e-records.local-ip.test. 300 IN TXT "local-ip.sh e2e" "second string"`,
				"e2e-records.local-ip.test. 300 IN MX 10 mail.example.net.",
				`e2e-records.local-ip.test. 300 IN CAA 0 issue ";"`,
				"e2e-alias.local-ip.test. 600 IN CNAME target.example.net.",
				"_e2e._tcp.local-ip.test. 300 IN SRV 0 0 443 target.example.net.",
				`local-ip.test. 300 IN TXT "local-ip.sh test instance"`,
			}, append(rigTXTRecords("e2e-txt-udp", 4), rigTXTRecords("e2e-txt-tcp", 12)...)...),
			recordSets: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			path := tt.path
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			server := zoneServer{origin: tt.origin, nameServers: tt.nameServers, challengeName: tt.challengeName, addresses: tt.addresses}
			file, err := parseZoneFile(strings.NewReader(string(content)), path, server)
			if err != nil {
				t.Fatal(err)
			}
			cuts := file.cuts.sortedCuts()
			if !slices.Equal(cuts, tt.cuts) {
				t.Errorf("cuts = %v, want %v", cuts, tt.cuts)
			}
			if got, want := stringsOf(file.records), rrStrings(t, tt.records...); !slices.Equal(got, want) {
				t.Errorf("records = %q\nwant      %q", got, want)
			}
			if got := recordSetCount(file.records); got != tt.recordSets {
				t.Errorf("%d record sets, want %d", got, tt.recordSets)
			}
			if !tt.hosted {
				return
			}
			for _, cut := range cuts {
				if !isProjectCut(cut, tt.origin) {
					t.Errorf("%s delegates %s: only labels starting with %q may be delegated on the hosted instance, because a delegation takes users' names below the label away from the service", tt.path, cut, projectLabelPrefix)
				}
			}
		})
	}
}

func TestRepositoryZoneFilesHostedDKIMRecord(t *testing.T) {
	const owner = "202411r._domainkey.local-ip.sh."
	path := filepath.Join("..", "zones", "local-ip.sh.zone")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	server := zoneServer{origin: "local-ip.sh", nameServers: []string{"ns1.local-ip.sh.", "ns2.local-ip.sh."}, challengeName: "_acme-challenge.local-ip.sh."}
	file, err := parseZoneFile(strings.NewReader(string(content)), path, server)
	if err != nil {
		t.Fatal(err)
	}

	var dkim []*dns.TXT
	for _, rr := range file.records {
		if txt, ok := rr.(*dns.TXT); ok && rr.Header().Name == owner {
			dkim = append(dkim, txt)
		}
	}
	if len(dkim) != 1 {
		t.Fatalf("got %d TXT records at %s, want 1", len(dkim), owner)
	}

	t.Run("its strings joined are the mail server's key", func(t *testing.T) {
		if got := strings.Join(dkim[0].Txt, ""); got != hostedRSADKIMValue {
			t.Errorf("DKIM value = %q, want %q", got, hostedRSADKIMValue)
		}
	})
	t.Run("its strings are cut every 255 octets", func(t *testing.T) {
		if got, want := dkim[0].Txt, chunkBy(hostedRSADKIMValue, 255); !slices.Equal(got, want) {
			t.Errorf("strings = %q, want %q", got, want)
		}
	})
	t.Run("its answer fits in a UDP reply without EDNS", func(t *testing.T) {
		if size := answerSizeOf(t, owner, dkim[0].String()); size > classicUDPLimit {
			t.Errorf("the answer for %s TXT takes %d octets, more than %d", owner, size, classicUDPLimit)
		}
	})
}
