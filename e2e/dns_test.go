package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	for i, tc := range cases {
		silent := false
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
			t.Fatalf("%s stopped answering DNS queries; %d of its %d cases were not run", server, len(cases)-i-1, len(cases))
		}
	}
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
