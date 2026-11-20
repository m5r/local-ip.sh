package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/miekg/dns"
)

const dnsAttemptTimeout = 3 * time.Second

// dnsRetryPauses holds the pause before each retry, so its length plus one is the number of
// attempts. Production is intermittently slow and lossy for tens of seconds at a time; the growing
// pauses ride out such an episode while every lost attempt is still logged.
var dnsRetryPauses = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second}

// errNoDNSResponse marks a question for which every attempt was lost, as opposed to one that got a
// wrong or unusable answer.
var errNoDNSResponse = errors.New("no DNS response received")

var publicResolvers = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("8.8.8.8"),
	netip.MustParseAddr("9.9.9.10"),
}

// exchange sends one question over UDP and returns the first response it gets. Only timeouts and
// network errors are retried; any decoded response is final whatever its rcode, so a wrong answer
// is never hidden by a retry. A response is returned together with an error when it does not echo
// the question or is truncated, since there is no TCP fallback to complete it.
func exchange(t *testing.T, server netip.Addr, name string, qtype uint16, recursion bool) (*dns.Msg, error) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	query.RecursionDesired = recursion

	client := &dns.Client{Net: "udp", Timeout: dnsAttemptTimeout}
	address := netip.AddrPortFrom(server, 53).String()
	question := name + " " + dns.TypeToString[qtype]
	attempts := len(dnsRetryPauses) + 1

	var lastErr error
	made := 0
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 && !pause(t.Context(), dnsRetryPauses[attempt-2]) {
			break
		}
		made = attempt
		query.Id = dns.Id()

		started := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), dnsAttemptTimeout)
		resp, _, err := client.ExchangeContext(ctx, query, address)
		cancel()
		if err == nil {
			if err := checkQuestionEcho(resp, name, qtype); err != nil {
				return resp, fmt.Errorf("response from %s for %s: %w", address, question, err)
			}
			if resp.Truncated {
				return resp, fmt.Errorf("response from %s for %s is truncated (TC bit set)", address, question)
			}
			return resp, nil
		}

		t.Logf("DNS attempt %d/%d to %s for %s failed after %s: %v", attempt, attempts, address, question, time.Since(started).Round(time.Millisecond), err)
		var netErr net.Error
		if !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &netErr) {
			return nil, fmt.Errorf("querying %s for %s: %w", address, question, err)
		}
		lastErr = err
		if t.Context().Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("%w from %s for %s after %d attempt(s), last error: %w", errNoDNSResponse, address, question, made, lastErr)
}

func pause(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func checkQuestionEcho(resp *dns.Msg, name string, qtype uint16) error {
	if len(resp.Question) != 1 {
		return fmt.Errorf("question section has %d entries, want 1", len(resp.Question))
	}
	q := resp.Question[0]
	if q.Name != name || q.Qtype != qtype || q.Qclass != dns.ClassINET {
		return fmt.Errorf("question section is %q %s %s, want %q %s IN", q.Name, dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass], name, dns.TypeToString[qtype])
	}
	return nil
}

// recordsOfType requires every record in rrs to be of the expected type, class IN and owned by
// name (compared case-insensitively), so stray records cannot hide among the expected ones.
func recordsOfType[T dns.RR](rrs []dns.RR, name string, rrtype uint16) ([]T, error) {
	records := make([]T, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		record, ok := rr.(T)
		if !ok || hdr.Rrtype != rrtype {
			return nil, fmt.Errorf("record %q is not of type %s", rr, dns.TypeToString[rrtype])
		}
		if hdr.Class != dns.ClassINET {
			return nil, fmt.Errorf("record %q has class %s, want IN", rr, dns.ClassToString[hdr.Class])
		}
		if !strings.EqualFold(hdr.Name, name) {
			return nil, fmt.Errorf("record %q is owned by %q, want %q", rr, hdr.Name, name)
		}
		records = append(records, record)
	}
	return records, nil
}

func aAddrs(records []*dns.A) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(records))
	for _, record := range records {
		addr, ok := netip.AddrFromSlice(record.A)
		if !ok {
			continue
		}
		addrs = append(addrs, addr.Unmap())
	}
	return addrs
}

func lookupA(t *testing.T, server netip.Addr, name string) ([]netip.Addr, error) {
	t.Helper()
	resp, err := exchange(t, server, name, dns.TypeA, false)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s answered %s for %s A, want NOERROR", server, dns.RcodeToString[resp.Rcode], name)
	}
	if !resp.Authoritative {
		return nil, fmt.Errorf("%s answered %s A without the AA flag", server, name)
	}
	records, err := recordsOfType[*dns.A](resp.Answer, name, dns.TypeA)
	if err != nil {
		return nil, fmt.Errorf("%s answer for %s A: %w", server, name, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s returned no A record for %s", server, name)
	}
	return aAddrs(records), nil
}

type dnsCase struct {
	name          string
	qname         string
	qtype         uint16
	rcodes        []int
	authoritative bool
	check         func(t *testing.T, resp *dns.Msg)
}

// runDNSCases stops at the first case that got no response at all: the server has gone silent, and
// running its remaining cases would only spend a full retry budget on each of them.
func runDNSCases(t *testing.T, server netip.Addr, recursion bool, cases []dnsCase) {
	t.Helper()
	if notRun, silent := runDNSCasesUntilSilent(t, server, recursion, cases); silent {
		t.Fatalf("%s stopped answering DNS queries; %d of its %d cases were not run", server, notRun, len(cases))
	}
}

// runDNSCasesUntilSilent runs the cases as subtests until one gets no response at all, and reports
// whether that happened and how many cases were left unrun.
func runDNSCasesUntilSilent(t *testing.T, server netip.Addr, recursion bool, cases []dnsCase) (notRun int, silent bool) {
	t.Helper()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := exchange(t, server, tc.qname, tc.qtype, recursion)
			if err != nil {
				silent = errors.Is(err, errNoDNSResponse)
				if resp != nil {
					t.Logf("response:\n%s", resp)
				}
				t.Fatal(err)
			}
			defer func() {
				if t.Failed() {
					t.Logf("response from %s:\n%s", server, resp)
				}
			}()

			if !slices.Contains(tc.rcodes, resp.Rcode) {
				names := make([]string, len(tc.rcodes))
				for i, rcode := range tc.rcodes {
					names[i] = dns.RcodeToString[rcode]
				}
				t.Errorf("rcode = %s, want one of %v", dns.RcodeToString[resp.Rcode], names)
			}
			if tc.authoritative && !resp.Authoritative {
				t.Error("AA flag is not set")
			}
			if tc.check != nil {
				tc.check(t, resp)
			}
		})
		if silent {
			return len(cases) - i - 1, true
		}
	}
	return 0, false
}

func expectA(want netip.Addr) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		records, err := recordsOfType[*dns.A](resp.Answer, resp.Question[0].Name, dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("got %d answers, want exactly 1", len(records))
		}
		if got := aAddrs(records); !slices.Equal(got, []netip.Addr{want}) {
			t.Errorf("A = %v, want %s", got, want)
		}
	}
}

func expectASet(want []netip.Addr) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		records, err := recordsOfType[*dns.A](resp.Answer, resp.Question[0].Name, dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		got := slices.SortedFunc(slices.Values(aAddrs(records)), netip.Addr.Compare)
		wantSorted := slices.SortedFunc(slices.Values(want), netip.Addr.Compare)
		if len(got) != len(records) || !slices.Equal(got, wantSorted) {
			t.Errorf("A answers = %v, want %v (any order)", got, wantSorted)
		}
	}
}

func expectNS(hosts []string, glue []netip.Addr) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		records, err := recordsOfType[*dns.NS](resp.Answer, resp.Question[0].Name, dns.TypeNS)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, len(records))
		for i, record := range records {
			got[i] = strings.ToLower(record.Ns)
		}
		slices.Sort(got)
		want := make([]string, len(hosts))
		for i, host := range hosts {
			want[i] = strings.ToLower(host)
		}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("NS targets = %v, want %v (any order)", got, want)
		}

		if glue == nil {
			return
		}
		for i, host := range hosts {
			found := false
			for _, rr := range resp.Extra {
				a, ok := rr.(*dns.A)
				if !ok || a.Hdr.Class != dns.ClassINET || !strings.EqualFold(a.Hdr.Name, host) {
					continue
				}
				if addr, ok := netip.AddrFromSlice(a.A); ok && addr.Unmap() == glue[i] {
					found = true
				}
			}
			if !found {
				t.Errorf("additional section has no A record %s for %s", glue[i], host)
			}
		}
	}
}

func expectSOA(ns, rname string) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		records, err := recordsOfType[*dns.SOA](resp.Answer, resp.Question[0].Name, dns.TypeSOA)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 1 {
			t.Fatalf("got %d SOA answers, want exactly 1", len(records))
		}
		if !strings.EqualFold(records[0].Ns, ns) {
			t.Errorf("SOA MNAME = %q, want %q", records[0].Ns, ns)
		}
		if records[0].Mbox != rname {
			t.Errorf("SOA RNAME = %q, want %q", records[0].Mbox, rname)
		}
	}
}

func expectNoAnswers(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers, want none", len(resp.Answer))
	}
}

// alternateCase upper-cases every other letter so the server is exercised with a mixed-case
// query name, as resolvers using 0x20 encoding send.
func alternateCase(name string) string {
	var b strings.Builder
	upper := true
	for _, r := range name {
		if unicode.IsLetter(r) {
			if upper {
				r = unicode.ToUpper(r)
			} else {
				r = unicode.ToLower(r)
			}
			upper = !upper
		}
		b.WriteRune(r)
	}
	return b.String()
}

func randomLabel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating random label: %v", err)
	}
	return "e2e-" + hex.EncodeToString(b)
}

func authoritativeAnswers(t *testing.T, tg *target) {
	zone := tg.zone()
	hosts := tg.nameServerHosts()
	want := netip.MustParseAddr("10.11.12.13")
	noError := []int{dns.RcodeSuccess}

	for _, server := range tg.nameServers {
		t.Run(server.String(), func(t *testing.T) {
			cases := []dnsCase{
				{name: "dashed", qname: "10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
				{name: "dashed with prefix", qname: "app.10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
				{name: "dotted", qname: "10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
				{name: "dotted with prefix", qname: "foo.bar.10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
				{name: "apex A", qname: zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectASet(tg.nameServers)},
			}
			for i, host := range hosts {
				cases = append(cases, dnsCase{name: fmt.Sprintf("ns%d A", i+1), qname: host, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(tg.nameServers[i])})
			}
			cases = append(cases,
				dnsCase{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: expectNS(hosts, tg.nameServers)},
				dnsCase{name: "apex SOA", qname: zone, qtype: dns.TypeSOA, rcodes: noError, authoritative: true, check: expectSOA(hosts[0], tg.soaRname())},
				dnsCase{name: "dashed AAAA", qname: "10-11-12-13." + zone, qtype: dns.TypeAAAA, rcodes: noError, authoritative: true, check: expectNoAnswers},
				dnsCase{name: "unknown name", qname: "nope." + zone, qtype: dns.TypeA, rcodes: []int{dns.RcodeSuccess, dns.RcodeNameError}, check: expectNoAnswers},
				dnsCase{name: "mixed case dashed with prefix", qname: alternateCase("app.10-11-12-13." + zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
				dnsCase{name: "mixed case apex A", qname: alternateCase(zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectASet(tg.nameServers)},
				dnsCase{name: "mixed case ns1 A", qname: alternateCase(hosts[0]), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(tg.nameServers[0])},
				dnsCase{name: "outside zone", qname: "example.com.", qtype: dns.TypeA, rcodes: []int{dns.RcodeRefused}},
			)
			runDNSCases(t, server, false, cases)
		})
	}
}

func publicResolverAnswers(t *testing.T, tg *target) {
	zone := tg.zone()
	noError := []int{dns.RcodeSuccess}

	for _, resolver := range publicResolvers {
		t.Run(resolver.String(), func(t *testing.T) {
			runDNSCases(t, resolver, true, []dnsCase{
				{name: "dashed with random prefix", qname: randomLabel(t) + ".10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(netip.MustParseAddr("10.11.12.13"))},
				{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, check: expectNS(tg.nameServerHosts(), nil)},
			})
		})
	}
}

func delegationChecks(t *testing.T, tg *target) {
	if len(tg.delegations) == 0 {
		t.Skipf("%s declares no delegations in its zone file", tg.app)
	}
	noError := []int{dns.RcodeSuccess}

	for _, server := range tg.nameServers {
		t.Run(server.String(), func(t *testing.T) {
			for i, d := range tg.delegations {
				silent := false
				t.Run(d.cut, func(t *testing.T) {
					referral := expectReferral(d)
					cases := []dnsCase{
						{name: "cut NS", qname: d.cut, qtype: dns.TypeNS, rcodes: noError, check: referral},
						{name: "random name A", qname: randomLabel(t) + "." + d.cut, qtype: dns.TypeA, rcodes: noError, check: referral},
						{name: "dashed A", qname: "10-11-12-13." + d.cut, qtype: dns.TypeA, rcodes: noError, check: referral},
						{name: "ACME challenge TXT", qname: "_acme-challenge." + d.cut, qtype: dns.TypeTXT, rcodes: noError, check: referral},
						{name: "cut DS", qname: d.cut, qtype: dns.TypeDS, rcodes: noError, authoritative: true, check: expectNoNSInAuthority},
					}
					notRun, wentSilent := runDNSCasesUntilSilent(t, server, false, cases)
					if wentSilent {
						silent = true
						t.Fatalf("%s stopped answering DNS queries; %d of the %d cases for %s were not run", server, notRun, len(cases), d.cut)
					}
				})
				if silent {
					t.Fatalf("%s stopped answering DNS queries; the checks of %d of its %d delegations were not run", server, len(tg.delegations)-i-1, len(tg.delegations))
				}
			}
		})
	}
}

// expectReferral checks a referral to the delegation: dnsCase.authoritative only asserts that AA
// is set, so the cleared AA flag is checked here.
func expectReferral(d targetDelegation) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		if resp.Authoritative {
			t.Errorf("AA flag is set, want it clear on a referral to %s", d.cut)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("got %d answers, want none in a referral to %s", len(resp.Answer), d.cut)
		}

		records, err := recordsOfType[*dns.NS](resp.Ns, d.cut, dns.TypeNS)
		if err != nil {
			t.Errorf("authority section, want only the NS records of %s: %v", d.cut, err)
		} else {
			got := make([]string, len(records))
			for i, record := range records {
				got[i] = strings.ToLower(record.Ns)
			}
			slices.Sort(got)
			want := slices.Sorted(slices.Values(d.nameServers))
			if !slices.Equal(got, want) {
				t.Errorf("authority NS targets = %v, want %v (any order)", got, want)
			}
		}

		for _, nameServer := range slices.Sorted(maps.Keys(d.glue)) {
			for _, want := range d.glue[nameServer] {
				if !hasGlue(resp.Extra, nameServer, want) {
					t.Errorf("additional section has no glue record %s for %s, want one", want, nameServer)
				}
			}
		}
	}
}

// hasGlue reports whether extra holds the glue record for want: an A record for an IPv4 address
// and an AAAA record for an IPv6 one, so an IPv4-mapped AAAA record cannot stand in for missing A
// glue.
func hasGlue(extra []dns.RR, nameServer string, want netip.Addr) bool {
	for _, rr := range extra {
		if rr.Header().Class != dns.ClassINET || !strings.EqualFold(rr.Header().Name, nameServer) {
			continue
		}
		switch record := rr.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(record.A); ok && want.Is4() && addr.Unmap() == want {
				return true
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(record.AAAA); ok && want.Is6() && addr == want {
				return true
			}
		}
	}
	return false
}

func expectNoNSInAuthority(t *testing.T, resp *dns.Msg) {
	t.Helper()
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeNS {
			t.Errorf("authority section contains the NS record %q, want no NS record outside a referral", rr)
		}
	}
}

func TestExpectReferralAcceptsWellFormedReferral(t *testing.T) {
	d := targetDelegation{
		cut:         "sub.example.com.",
		nameServers: []string{"ns1.sub.example.com.", "ns.other.test."},
		glue:        map[string][]netip.Addr{"ns1.sub.example.com.": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}},
	}
	resp := new(dns.Msg)
	resp.SetQuestion("WwW.SuB.ExAmPlE.CoM.", dns.TypeA)
	resp.Response = true
	for _, record := range []string{"SUB.example.com. 300 IN NS NS.OTHER.TEST.", "sub.example.com. 300 IN NS ns1.sub.example.com."} {
		resp.Ns = append(resp.Ns, mustRR(t, record))
	}
	for _, record := range []string{"ns1.sub.example.com. 300 IN AAAA 2001:db8::1", "ns1.sub.example.com. 300 IN A 192.0.2.1"} {
		resp.Extra = append(resp.Extra, mustRR(t, record))
	}
	resp.SetEdns0(1232, false)

	expectReferral(d)(t, resp)
}

func mustRR(t *testing.T, record string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatalf("parsing %q: %v", record, err)
	}
	return rr
}

func TestHasGlue(t *testing.T) {
	const nameServer = "ns1.sub.example.com."
	tests := []struct {
		name  string
		extra []string
		want  string
		found bool
	}{
		{name: "A record for IPv4 glue", extra: []string{"ns1.sub.example.com. 300 IN A 192.0.2.1"}, want: "192.0.2.1", found: true},
		{name: "AAAA record for IPv6 glue", extra: []string{"ns1.sub.example.com. 300 IN AAAA 2001:db8::1"}, want: "2001:db8::1", found: true},
		{name: "owner in a different case", extra: []string{"NS1.Sub.Example.COM. 300 IN A 192.0.2.1"}, want: "192.0.2.1", found: true},
		{name: "IPv4-mapped AAAA record instead of A glue", extra: []string{"ns1.sub.example.com. 300 IN AAAA ::ffff:192.0.2.1"}, want: "192.0.2.1", found: false},
		{name: "A record for IPv4-mapped IPv6 glue", extra: []string{"ns1.sub.example.com. 300 IN A 192.0.2.1"}, want: "::ffff:192.0.2.1", found: false},
		{name: "A record of another name server", extra: []string{"ns2.sub.example.com. 300 IN A 192.0.2.1"}, want: "192.0.2.1", found: false},
		{name: "A record with another address", extra: []string{"ns1.sub.example.com. 300 IN A 192.0.2.2"}, want: "192.0.2.1", found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var extra []dns.RR
			for _, record := range tt.extra {
				extra = append(extra, mustRR(t, record))
			}
			if got := hasGlue(extra, nameServer, netip.MustParseAddr(tt.want)); got != tt.found {
				t.Errorf("hasGlue(%q, %s) = %t, want %t", tt.extra, tt.want, got, tt.found)
			}
		})
	}
}
