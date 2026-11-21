package e2e

import (
	"cmp"
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

// dnsQuery is one question and the header flags it is sent with.
type dnsQuery struct {
	name             string
	qtype            uint16
	qclass           uint16
	recursion        bool
	checkingDisabled bool
}

func (q dnsQuery) String() string {
	return fmt.Sprintf("%s %s %s", q.name, dns.Class(q.qclass), dns.Type(q.qtype))
}

// exchange sends one question over UDP and returns the first response it gets. Only timeouts and
// network errors are retried; any decoded response is final whatever its rcode, so a wrong answer
// is never hidden by a retry. A response is returned together with an error when it does not echo
// the question or is truncated, since there is no TCP fallback to complete it.
func exchange(t *testing.T, server netip.Addr, q dnsQuery) (*dns.Msg, error) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(q.name, q.qtype)
	query.Question[0].Qclass = q.qclass
	query.RecursionDesired = q.recursion
	query.CheckingDisabled = q.checkingDisabled

	client := &dns.Client{Net: "udp", Timeout: dnsAttemptTimeout}
	address := netip.AddrPortFrom(server, 53).String()
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
			if err := checkQuestionEchoOfClass(resp, q.name, q.qtype, q.qclass); err != nil {
				return resp, fmt.Errorf("response from %s for %s: %w", address, q, err)
			}
			if err := checkReplyHeader(q, resp); err != nil {
				return resp, fmt.Errorf("response from %s for %s: %w", address, q, err)
			}
			if resp.Truncated {
				return resp, fmt.Errorf("response from %s for %s is truncated (TC bit set)", address, q)
			}
			return resp, nil
		}

		t.Logf("DNS attempt %d/%d to %s for %s failed after %s: %v", attempt, attempts, address, q, time.Since(started).Round(time.Millisecond), err)
		var netErr net.Error
		if !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &netErr) {
			return nil, fmt.Errorf("querying %s for %s: %w", address, q, err)
		}
		lastErr = err
		if t.Context().Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("%w from %s for %s after %d attempt(s), last error: %w", errNoDNSResponse, address, q, made, lastErr)
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

// checkReplyHeader checks the header fields every reply to the query must have: the client matches a reply by its id alone, so a message that is no reply to a standard query, or one that does not copy the RD flag of the query (B3), would otherwise pass.
func checkReplyHeader(q dnsQuery, resp *dns.Msg) error {
	if !resp.Response {
		return errors.New("QR flag is clear, want it set on a reply")
	}
	if resp.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("opcode = %s, want QUERY", dns.OpcodeToString[resp.Opcode])
	}
	if resp.RecursionDesired != q.recursion {
		return fmt.Errorf("RD flag = %t, want %t as in the query", resp.RecursionDesired, q.recursion)
	}
	return nil
}

// checkQuestionEcho checks the echo of a question in class IN, the only class the prober asks in.
func checkQuestionEcho(resp *dns.Msg, name string, qtype uint16) error {
	return checkQuestionEchoOfClass(resp, name, qtype, dns.ClassINET)
}

func checkQuestionEchoOfClass(resp *dns.Msg, name string, qtype, qclass uint16) error {
	if len(resp.Question) != 1 {
		return fmt.Errorf("question section has %d entries, want 1", len(resp.Question))
	}
	q := resp.Question[0]
	if q.Name != name || q.Qtype != qtype || q.Qclass != qclass {
		return fmt.Errorf("question section is %q %s %s, want %q %s %s", q.Name, dns.Class(q.Qclass), dns.Type(q.Qtype), name, dns.Class(qclass), dns.Type(qtype))
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
	resp, err := exchange(t, server, dnsQuery{name: name, qtype: dns.TypeA, qclass: dns.ClassINET})
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
	name  string
	qname string
	qtype uint16
	// qclass is IN when unset.
	qclass           uint16
	checkingDisabled bool
	rcodes           []int
	authoritative    bool
	nonAuthoritative bool
	// fromZoneFile marks a case generated from a declaration of the zone file, whose name is declared by construction.
	fromZoneFile bool
	check        func(t *testing.T, resp *dns.Msg)
}

// dnsPath says how a case's query reaches the zone.
type dnsPath int

const (
	// toNameServer sends the query straight to one of the target's name servers, without the RD flag.
	toNameServer dnsPath = iota
	// throughResolver sends the query to a public resolver, with the RD flag.
	throughResolver
)

func (tc dnsCase) query(path dnsPath) dnsQuery {
	q := dnsQuery{name: tc.qname, qtype: tc.qtype, qclass: tc.qclass, recursion: path == throughResolver, checkingDisabled: tc.checkingDisabled}
	if q.qclass == 0 {
		q.qclass = dns.ClassINET
	}
	return q
}

// checkReplyOnPath checks the AA flag a case asks for, the owners of the answer records and, on a reply straight from a name server, the flags an authoritative-only server without DNSSEC never sets: it offers no recursion, validates nothing and so must not echo CD.
// A name server owns its answer records by the question name exactly as asked (B4), which is also what keeps a reply within 512 octets whatever the case of the question; a resolver may spell the owner its own way.
func checkReplyOnPath(tc dnsCase, path dnsPath, resp *dns.Msg) error {
	var problems []error
	if len(resp.Question) == 1 {
		qname := resp.Question[0].Name
		for _, rr := range resp.Answer {
			owner := rr.Header().Name
			if path == toNameServer && owner != qname {
				problems = append(problems, fmt.Errorf("answer record %q is owned by %q, want the question name exactly as asked, %q", rr, owner, qname))
			}
			if path == throughResolver && !strings.EqualFold(owner, qname) {
				problems = append(problems, fmt.Errorf("answer record %q is owned by %q, want the question name %q", rr, owner, qname))
			}
		}
	}
	if tc.authoritative && !resp.Authoritative {
		problems = append(problems, errors.New("AA flag is not set"))
	}
	if tc.nonAuthoritative && resp.Authoritative {
		problems = append(problems, errors.New("AA flag is set, want it clear"))
	}
	if path == toNameServer {
		if resp.RecursionAvailable {
			problems = append(problems, errors.New("RA flag is set, want it clear from an authoritative-only server"))
		}
		if resp.AuthenticatedData {
			problems = append(problems, errors.New("AD flag is set, want it clear from a server without DNSSEC"))
		}
		if resp.CheckingDisabled {
			problems = append(problems, errors.New("CD flag is set, want it clear from a server without DNSSEC"))
		}
	}
	return errors.Join(problems...)
}

// runDNSCases stops at the first case that got no response at all: the server has gone silent, and
// running its remaining cases would only spend a full retry budget on each of them.
func runDNSCases(t *testing.T, server netip.Addr, path dnsPath, cases []dnsCase) {
	t.Helper()
	if notRun, silent := runDNSCasesUntilSilent(t, server, path, cases); silent {
		t.Fatalf("%s stopped answering DNS queries; %d of its %d cases were not run", server, notRun, len(cases))
	}
}

// runDNSCasesUntilSilent runs the cases as subtests until one gets no response at all, and reports
// whether that happened and how many cases were left unrun.
func runDNSCasesUntilSilent(t *testing.T, server netip.Addr, path dnsPath, cases []dnsCase) (notRun int, silent bool) {
	t.Helper()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := exchange(t, server, tc.query(path))
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
			if err := checkReplyOnPath(tc, path, resp); err != nil {
				t.Error(err)
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

// asCheck turns a check that returns an error into the form of dnsCase.check.
func asCheck(check func(*dns.Msg) error) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		if err := check(resp); err != nil {
			t.Error(err)
		}
	}
}

// checkNoData checks the NODATA form of RFC 2308: NOERROR, no answer, and the zone's SOA record alone in the authority section.
func checkNoData(zoneSOA *dns.SOA, resp *dns.Msg) error {
	return checkNegative(zoneSOA, resp, dns.RcodeSuccess)
}

// checkNameError checks the NXDOMAIN form of RFC 2308, which has the sections of NODATA.
func checkNameError(zoneSOA *dns.SOA, resp *dns.Msg) error {
	return checkNegative(zoneSOA, resp, dns.RcodeNameError)
}

// checkNegative compares the SOA record of a negative answer with zoneSOA, the record the same name server gives for the zone's SOA question: RFC 2308 section 3 asks for that record with a TTL of the smaller of its own TTL and its MINIMUM field, so the check holds the reply to the server's own data instead of to constants of its code.
func checkNegative(zoneSOA *dns.SOA, resp *dns.Msg, rcode int) error {
	if resp.Rcode != rcode {
		return fmt.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
	}
	if len(resp.Answer) != 0 {
		return fmt.Errorf("answer section has %d records, want none", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		return fmt.Errorf("authority section has %d records, want exactly the SOA record of %s", len(resp.Ns), zoneSOA.Hdr.Name)
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		return fmt.Errorf("authority record %q is not an SOA record", resp.Ns[0])
	}
	if soa.Hdr.Class != dns.ClassINET {
		return fmt.Errorf("SOA record %q has class %s, want IN", soa, dns.Class(soa.Hdr.Class))
	}
	if !strings.EqualFold(soa.Hdr.Name, zoneSOA.Hdr.Name) {
		return fmt.Errorf("SOA record is owned by %q, want the zone %q", soa.Hdr.Name, zoneSOA.Hdr.Name)
	}
	if got, want := soaFields(soa), soaFields(zoneSOA); got != want {
		return fmt.Errorf("SOA record has %s, want the zone's SOA record, %s", got, want)
	}
	if want := min(zoneSOA.Hdr.Ttl, zoneSOA.Minttl); soa.Hdr.Ttl != want {
		return fmt.Errorf("SOA TTL = %d, want %d, the smaller of the zone's SOA TTL %d and its MINIMUM field %d", soa.Hdr.Ttl, want, zoneSOA.Hdr.Ttl, zoneSOA.Minttl)
	}
	if len(resp.Extra) != 0 {
		return fmt.Errorf("additional section has %d records, want none", len(resp.Extra))
	}
	return nil
}

// soaFields spells every RDATA field of an SOA record.
func soaFields(soa *dns.SOA) string {
	return fmt.Sprintf("MNAME %s, RNAME %s, serial %d, refresh %d, retry %d, expire %d, minimum %d", soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
}

// zoneSOA asks a name server for the zone's SOA record, which its negative answers must carry.
func zoneSOA(t *testing.T, server netip.Addr, tg *target) (*dns.SOA, error) {
	t.Helper()
	resp, err := exchange(t, server, dnsQuery{name: tg.zone(), qtype: dns.TypeSOA, qclass: dns.ClassINET})
	if err != nil {
		return nil, err
	}
	soa, err := referenceSOA(tg, resp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", server, err)
	}
	return soa, nil
}

// referenceSOA takes the record the negative answers are compared with from a name server's reply to the zone's SOA question, after holding that reply to everything the "apex SOA" case requires: otherwise the negative answers could be held to a record with another MNAME or RNAME than the target's, or to one from a reply that is not a proper authoritative answer.
func referenceSOA(tg *target, resp *dns.Msg) (*dns.SOA, error) {
	if err := checkReplyOnPath(dnsCase{authoritative: true}, toNameServer, resp); err != nil {
		return nil, fmt.Errorf("reply to %s SOA: %w", tg.zone(), err)
	}
	return apexSOA(tg, resp)
}

// apexSOA holds an answer to the zone's SOA question to the target and returns its SOA record; the numbers of the record are the server's own and are not pinned.
func apexSOA(tg *target, resp *dns.Msg) (*dns.SOA, error) {
	zone := tg.zone()
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("answered %s for %s SOA, want NOERROR", dns.RcodeToString[resp.Rcode], zone)
	}
	records, err := recordsOfType[*dns.SOA](resp.Answer, zone, dns.TypeSOA)
	if err != nil {
		return nil, fmt.Errorf("answer for %s SOA: %w", zone, err)
	}
	if len(records) != 1 {
		return nil, fmt.Errorf("returned %d SOA records for %s, want exactly 1", len(records), zone)
	}
	soa := records[0]
	if want := tg.nameServerHosts()[0]; !strings.EqualFold(soa.Ns, want) {
		return nil, fmt.Errorf("SOA MNAME = %q, want %q", soa.Ns, want)
	}
	if soa.Mbox != tg.soaRname() {
		return nil, fmt.Errorf("SOA RNAME = %q, want %q", soa.Mbox, tg.soaRname())
	}
	return soa, nil
}

func expectApexSOA(tg *target) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error {
		_, err := apexSOA(tg, resp)
		return err
	})
}

// requireZoneSOA gives the cases of one name server the SOA record their negative answers are compared with, and ends that name server's run when it cannot.
func requireZoneSOA(t *testing.T, server netip.Addr, tg *target) *dns.SOA {
	t.Helper()
	soa, err := zoneSOA(t, server, tg)
	if err != nil {
		t.Fatalf("cannot check the negative answers of %s without its SOA record for %s: %v", server, tg.zone(), err)
	}
	return soa
}

// checkRecordSet checks an answer that carries the declared record set, owned by the question name.
func checkRecordSet(set targetRecordSet, resp *dns.Msg) error {
	if len(resp.Question) != 1 {
		return fmt.Errorf("question section has %d entries, want 1", len(resp.Question))
	}
	qname := resp.Question[0].Name
	got := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		hdr := rr.Header()
		if hdr.Rrtype != set.rrtype {
			return fmt.Errorf("answer record %q is not of type %s", rr, dns.Type(set.rrtype))
		}
		if hdr.Class != dns.ClassINET {
			return fmt.Errorf("answer record %q has class %s, want IN", rr, dns.Class(hdr.Class))
		}
		if !strings.EqualFold(hdr.Name, qname) {
			return fmt.Errorf("answer record %q is owned by %q, want the question name %q", rr, hdr.Name, qname)
		}
		if hdr.Ttl != set.ttl {
			return fmt.Errorf("answer record %q has TTL %d, want the declared %d", rr, hdr.Ttl, set.ttl)
		}
		fields, err := rdataFields(rr)
		if err != nil {
			return err
		}
		got = append(got, fields)
	}
	want := make([]string, 0, len(set.records))
	for _, rr := range set.records {
		fields, err := rdataFields(rr)
		if err != nil {
			return fmt.Errorf("declared record: %w", err)
		}
		want = append(want, fields)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("answer RDATA = %q, want %q (any order)", got, want)
	}
	if len(resp.Ns) != 0 {
		return fmt.Errorf("authority section has %d records, want none", len(resp.Ns))
	}
	if len(resp.Extra) != 0 {
		return fmt.Errorf("additional section has %d records, want none", len(resp.Extra))
	}
	return nil
}

// rdataFields spells the RDATA of a record field by field, names in canonical form, so that two records compare equal exactly when their data does.
func rdataFields(rr dns.RR) (string, error) {
	switch record := rr.(type) {
	case *dns.A:
		addr, _ := netip.AddrFromSlice(record.A)
		return addr.Unmap().String(), nil
	case *dns.AAAA:
		addr, _ := netip.AddrFromSlice(record.AAAA)
		return addr.String(), nil
	case *dns.TXT:
		return fmt.Sprintf("%q", record.Txt), nil
	case *dns.MX:
		return fmt.Sprintf("preference %d, exchange %s", record.Preference, dns.CanonicalName(record.Mx)), nil
	case *dns.SRV:
		return fmt.Sprintf("priority %d, weight %d, port %d, target %s", record.Priority, record.Weight, record.Port, dns.CanonicalName(record.Target)), nil
	case *dns.CNAME:
		return dns.CanonicalName(record.Target), nil
	case *dns.CAA:
		return fmt.Sprintf("flag %d, tag %q, value %q", record.Flag, record.Tag, record.Value), nil
	case *dns.NS:
		return dns.CanonicalName(record.Ns), nil
	}
	return "", fmt.Errorf("record %q has a type the suite cannot compare", rr)
}

// checkHINFO checks the reply of RFC 8482 to a query for ANY at a name that owns records.
func checkHINFO(resp *dns.Msg) error {
	if len(resp.Question) != 1 {
		return fmt.Errorf("question section has %d entries, want 1", len(resp.Question))
	}
	if len(resp.Answer) != 1 {
		return fmt.Errorf("answer section has %d records, want exactly one HINFO record", len(resp.Answer))
	}
	hinfo, ok := resp.Answer[0].(*dns.HINFO)
	if !ok {
		return fmt.Errorf("answer record %q is not an HINFO record", resp.Answer[0])
	}
	if hinfo.Hdr.Class != dns.ClassINET {
		return fmt.Errorf("HINFO record %q has class %s, want IN", hinfo, dns.Class(hinfo.Hdr.Class))
	}
	if qname := resp.Question[0].Name; !strings.EqualFold(hinfo.Hdr.Name, qname) {
		return fmt.Errorf("HINFO record is owned by %q, want the question name %q", hinfo.Hdr.Name, qname)
	}
	if hinfo.Cpu != "RFC8482" || hinfo.Os != "" {
		return fmt.Errorf("HINFO CPU and OS = %q %q, want %q %q", hinfo.Cpu, hinfo.Os, "RFC8482", "")
	}
	if hinfo.Hdr.Ttl != 3600 {
		return fmt.Errorf("HINFO TTL = %d, want 3600", hinfo.Hdr.Ttl)
	}
	if len(resp.Ns) != 0 {
		return fmt.Errorf("authority section has %d records, want none", len(resp.Ns))
	}
	if len(resp.Extra) != 0 {
		return fmt.Errorf("additional section has %d records, want none", len(resp.Extra))
	}
	return nil
}

// checkNoRecords checks a refusal, which carries nothing but the question.
func checkNoRecords(resp *dns.Msg) error {
	if n := len(resp.Answer) + len(resp.Ns) + len(resp.Extra); n != 0 {
		return fmt.Errorf("reply has %d answer, %d authority and %d additional records, want none", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	}
	return nil
}

func expectNoData(zoneSOA *dns.SOA) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkNoData(zoneSOA, resp) })
}

func expectNameError(zoneSOA *dns.SOA) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkNameError(zoneSOA, resp) })
}

func expectRecordSet(set targetRecordSet) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkRecordSet(set, resp) })
}

var (
	expectHINFO     = asCheck(checkHINFO)
	expectNoRecords = asCheck(checkNoRecords)
)

// nameOfWireLength builds a name below the zone of exactly that many octets in wire format, from labels of x in front of the zone.
func nameOfWireLength(zone string, octets int) string {
	zoneOctets := wireLength(zone)
	remaining := octets - zoneOctets
	if remaining < 2 {
		panic(fmt.Sprintf("no name below %q has %d octets: the zone alone has %d", zone, octets, zoneOctets))
	}
	var labels []string
	for remaining > 0 {
		n := min(remaining-1, 63)
		if remaining-(n+1) == 1 {
			n--
		}
		labels = append(labels, strings.Repeat("x", n))
		remaining -= n + 1
	}
	return strings.Join(labels, ".") + "." + dns.Fqdn(zone)
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
	for _, server := range tg.nameServers {
		t.Run(server.String(), func(t *testing.T) {
			runDNSCases(t, server, toNameServer, authoritativeCases(tg, requireZoneSOA(t, server, tg)))
		})
	}
}

// authoritativeCases are the cases every name server of the target must answer from its zone; zoneSOA is that name server's SOA record for the zone, which the negative answers are compared with when the checks run.
func authoritativeCases(tg *target, zoneSOA *dns.SOA) []dnsCase {
	zone := tg.zone()
	hosts := tg.nameServerHosts()
	want := netip.MustParseAddr("10.11.12.13")
	noError := []int{dns.RcodeSuccess}
	refused := []int{dns.RcodeRefused}
	nameError := []int{dns.RcodeNameError}
	noData := expectNoData(zoneSOA)

	cases := []dnsCase{
		{name: "dashed", qname: "10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed with prefix", qname: "app.10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted", qname: "10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted with prefix", qname: "foo.bar.10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed with labels after the address", qname: "10-11-12-13.app." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted with labels after the address", qname: "10.11.12.13.app." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "apex A", qname: zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectASet(tg.nameServers)},
	}
	for i, host := range hosts {
		cases = append(cases, dnsCase{name: fmt.Sprintf("ns%d A", i+1), qname: host, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(tg.nameServers[i])})
	}
	cases = append(cases,
		dnsCase{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: expectNS(hosts, tg.nameServers)},
		dnsCase{name: "apex SOA", qname: zone, qtype: dns.TypeSOA, rcodes: noError, authoritative: true, check: expectApexSOA(tg)},
		dnsCase{name: "CD flag", qname: zone, qtype: dns.TypeSOA, checkingDisabled: true, rcodes: noError, authoritative: true, check: expectApexSOA(tg)},
		dnsCase{name: "dashed AAAA", qname: "10-11-12-13." + zone, qtype: dns.TypeAAAA, rcodes: noError, authoritative: true, check: noData},
	)
	for _, qtype := range []uint16{dns.TypeTXT, dns.TypeMX, dns.TypeCAA, dns.TypeHTTPS, dns.TypeDS, dns.TypeDNSKEY} {
		cases = append(cases, dnsCase{name: "dashed " + dns.Type(qtype).String(), qname: "10-11-12-13." + zone, qtype: qtype, rcodes: noError, authoritative: true, check: noData})
	}
	cases = append(cases,
		dnsCase{name: "NS below the apex", qname: "10-11-12-13." + zone, qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "SOA below the apex", qname: "app.10-11-12-13." + zone, qtype: dns.TypeSOA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "one number", qname: "13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "two numbers", qname: "12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "three numbers", qname: "11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "three numbers NS", qname: "11.12.13." + zone, qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "unknown name", qname: "nope." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "unknown name TXT", qname: "nope." + zone, qtype: dns.TypeTXT, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "mixed case unknown name", qname: alternateCase("nope." + zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "longest name that can have a child", qname: nameOfWireLength(zone, 253), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		dnsCase{name: "name of 254 octets is too long to have a child", qname: nameOfWireLength(zone, 254), qtype: dns.TypeA, rcodes: nameError, authoritative: true, check: expectNameError(zoneSOA)},
		dnsCase{name: "name of 255 octets is too long to have a child", qname: nameOfWireLength(zone, 255), qtype: dns.TypeA, rcodes: nameError, authoritative: true, check: expectNameError(zoneSOA)},
	)
	for _, qtype := range []uint16{dns.TypeDS, dns.TypeDNSKEY, 65280} {
		cases = append(cases, dnsCase{name: "apex " + dns.Type(qtype).String(), qname: zone, qtype: qtype, rcodes: noError, authoritative: true, check: noData})
	}
	cases = append(cases,
		dnsCase{name: "ANY at an address name", qname: "10-11-12-13." + zone, qtype: dns.TypeANY, rcodes: noError, authoritative: true, check: expectHINFO},
		dnsCase{name: "ANY at the apex", qname: zone, qtype: dns.TypeANY, rcodes: noError, authoritative: true, check: expectHINFO},
	)
	cases = append(cases, declaredRecordCases(tg, zoneSOA)...)
	cases = append(cases,
		dnsCase{name: "mixed case dashed with prefix", qname: alternateCase("app.10-11-12-13." + zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		dnsCase{name: "mixed case apex A", qname: alternateCase(zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectASet(tg.nameServers)},
		dnsCase{name: "mixed case ns1 A", qname: alternateCase(hosts[0]), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(tg.nameServers[0])},
	)
	unrelated, sibling := outsideNames(zone)
	cases = append(cases,
		dnsCase{name: "outside zone", qname: unrelated, qtype: dns.TypeA, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "outside zone sibling with the same suffix", qname: sibling, qtype: dns.TypeA, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "class CH", qname: zone, qtype: dns.TypeTXT, qclass: dns.ClassCHAOS, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "zone transfer AXFR", qname: zone, qtype: dns.TypeAXFR, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "zone transfer IXFR", qname: zone, qtype: dns.TypeIXFR, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
	)
	return cases
}

// declaredRecordCases asks for every record set the target's zone file declares, as written and in mixed case, and asks each name for a type it has none of. A CNAME is also asked for types it is not, which it answers in their place.
func declaredRecordCases(tg *target, zoneSOA *dns.SOA) []dnsCase {
	noError := []int{dns.RcodeSuccess}
	var cases []dnsCase
	var ownersWithoutCNAME []string
	for _, set := range tg.recordSets {
		label := set.owner + " " + dns.Type(set.rrtype).String()
		cases = append(cases,
			dnsCase{name: "declared " + label, qname: set.owner, qtype: set.rrtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)},
			dnsCase{name: "mixed case declared " + label, qname: alternateCase(set.owner), qtype: set.rrtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)},
		)
		if set.rrtype == dns.TypeCNAME {
			for _, qtype := range []uint16{dns.TypeA, dns.TypeNS} {
				cases = append(cases, dnsCase{name: "declared " + label + " asked for " + dns.Type(qtype).String(), qname: set.owner, qtype: qtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)})
			}
		} else if !slices.Contains(ownersWithoutCNAME, set.owner) {
			ownersWithoutCNAME = append(ownersWithoutCNAME, set.owner)
		}
	}
	// HTTPS is a type the zone file cannot declare, so every declared name lacks it.
	for _, owner := range ownersWithoutCNAME {
		cases = append(cases, dnsCase{name: "declared name " + owner + " asked for HTTPS", qname: owner, qtype: dns.TypeHTTPS, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectNoData(zoneSOA)})
	}
	return cases
}

func publicResolverAnswers(t *testing.T, tg *target) {
	for _, resolver := range publicResolvers {
		t.Run(resolver.String(), func(t *testing.T) {
			cases := publicResolverCases(tg, func() string { return randomLabel(t) })
			if err := checkProbeCases(tg, cases); err != nil {
				t.Fatal(err)
			}
			runDNSCases(t, resolver, throughResolver, cases)
		})
	}
}

// publicResolverCases are the cases every public resolver must answer for the target; label gives the random label that keeps a name out of the resolver's cache.
func publicResolverCases(tg *target, label func() string) []dnsCase {
	zone := tg.zone()
	noError := []int{dns.RcodeSuccess}
	want := netip.MustParseAddr("10.11.12.13")
	return []dnsCase{
		{name: "dashed with random prefix", qname: label() + ".10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(want)},
		// The resolver minimises the query name on its way and passes through 13.<zone>, 12.13.<zone> and 11.12.13.<zone>, which used to answer NXDOMAIN.
		{name: "dotted with random prefix", qname: label() + ".10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(want)},
		{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, check: expectNS(tg.nameServerHosts(), nil)},
	}
}

// outsideNames are two names outside the zone that every name server must refuse: an unrelated one, and a sibling that ends with the zone's name as a string but not at a label boundary, which only a label-by-label comparison refuses.
func outsideNames(zone string) (unrelated, sibling string) {
	unrelated = "example.com."
	if dns.IsSubDomain(zone, unrelated) {
		unrelated = "example.net."
	}
	labels := dns.SplitDomainName(zone)
	rest := strings.TrimPrefix(dns.Fqdn(zone), labels[0])
	// A first label of 63 octets, or a zone of 255 octets, has no room for one more octet, so the first octet is changed instead.
	if len(labels[0]) == 63 || wireLength(zone) == 255 {
		first := "x"
		if labels[0][0] == 'x' {
			first = "y"
		}
		return unrelated, first + labels[0][1:] + rest
	}
	return unrelated, "x" + labels[0] + rest
}

// wireLength is the length of a name in wire format.
func wireLength(name string) int {
	buf := make([]byte, 512)
	octets, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		panic(fmt.Sprintf("packing %q: %v", name, err))
	}
	return octets
}

// checkProbes holds the names the suite asks for against the target before any of them is asked.
// The suite reserves the names it probes below the apex: the zone file may neither declare a record at one nor delegate it or a name above it. Deciding for every case whether a declaration changes its expected answer (the type asked, a CNAME that answers every type, a record that makes a name of 254 octets exist) is more machinery than a handful of reserved names is worth.
// The names of the resolver cases are generated per run, so publicResolverAnswers checks them before it asks them.
func checkProbes(tg *target) error {
	zone := tg.zone()
	unrelated, sibling := outsideNames(zone)
	for _, name := range []string{unrelated, sibling} {
		if dns.IsSubDomain(zone, name) {
			return fmt.Errorf("the name %q the suite expects to be refused as outside the zone is inside %s", name, zone)
		}
	}
	return checkProbeCases(tg, authoritativeCases(tg, nil))
}

// checkProbeCases refuses a case whose name below the apex the zone file declares a record at or delegates, the names the suite reserves for its probes; a case generated from the zone file asks for a declared name by construction.
func checkProbeCases(tg *target, cases []dnsCase) error {
	zone := tg.zone()
	for _, tc := range cases {
		name := dns.CanonicalName(tc.qname)
		if tc.fromZoneFile || name == zone || !dns.IsSubDomain(zone, name) {
			continue
		}
		for _, set := range tg.recordSets {
			if set.owner == name {
				return fmt.Errorf("the name %s, which the case %q asks for, is reserved for the suite's probes, and the zone file declares %s %s there", name, tc.name, set.owner, dns.Type(set.rrtype))
			}
		}
		for _, d := range tg.delegations {
			if dns.IsSubDomain(d.cut, name) {
				return fmt.Errorf("the name %s, which the case %q asks for, is reserved for the suite's probes, and the zone file delegates it or a name above it: %s NS", name, tc.name, d.cut)
			}
		}
	}
	return nil
}

func delegationChecks(t *testing.T, tg *target) {
	if len(tg.delegations) == 0 {
		t.Skipf("%s declares no delegations in its zone file", tg.app)
	}
	noError := []int{dns.RcodeSuccess}

	for _, server := range tg.nameServers {
		t.Run(server.String(), func(t *testing.T) {
			soa := requireZoneSOA(t, server, tg)
			for i, d := range tg.delegations {
				silent := false
				t.Run(d.cut, func(t *testing.T) {
					referral := expectReferral(d)
					cases := []dnsCase{
						{name: "cut NS", qname: d.cut, qtype: dns.TypeNS, rcodes: noError, nonAuthoritative: true, check: referral},
						{name: "random name A", qname: randomLabel(t) + "." + d.cut, qtype: dns.TypeA, rcodes: noError, nonAuthoritative: true, check: referral},
						{name: "dashed A", qname: "10-11-12-13." + d.cut, qtype: dns.TypeA, rcodes: noError, nonAuthoritative: true, check: referral},
						{name: "ACME challenge TXT", qname: "_acme-challenge." + d.cut, qtype: dns.TypeTXT, rcodes: noError, nonAuthoritative: true, check: referral},
						// DS records belong to the parent, so this server answers for them from its own zone.
						{name: "cut DS", qname: d.cut, qtype: dns.TypeDS, rcodes: noError, authoritative: true, check: expectNoData(soa)},
					}
					notRun, wentSilent := runDNSCasesUntilSilent(t, server, toNameServer, cases)
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

// expectReferral checks the sections of a referral to the delegation; the cleared AA flag is a requirement of the case.
func expectReferral(d targetDelegation) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
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

const testSOA = "example.test. 300 IN SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"

// testReply builds a reply to qname and qtype with the records given in zone file syntax.
func testReply(t *testing.T, qname string, qtype uint16, rcode int, answer, authority, additional []string) *dns.Msg {
	t.Helper()
	resp := new(dns.Msg)
	resp.SetQuestion(qname, qtype)
	resp.Response = true
	resp.Authoritative = true
	resp.Rcode = rcode
	for _, section := range []struct {
		records []string
		into    *[]dns.RR
	}{{answer, &resp.Answer}, {authority, &resp.Ns}, {additional, &resp.Extra}} {
		for _, record := range section.records {
			*section.into = append(*section.into, mustRR(t, record))
		}
	}
	return resp
}

func TestCheckNegativeReplies(t *testing.T) {
	zoneSOA := mustRR(t, testSOA).(*dns.SOA)
	checks := []struct {
		name       string
		rcode      int
		otherRcode int
		check      func(*dns.SOA, *dns.Msg) error
	}{
		{name: "checkNoData", rcode: dns.RcodeSuccess, otherRcode: dns.RcodeNameError, check: checkNoData},
		{name: "checkNameError", rcode: dns.RcodeNameError, otherRcode: dns.RcodeSuccess, check: checkNameError},
	}
	soaField := func(set func(*dns.SOA)) func(*testing.T, *dns.Msg) {
		return func(_ *testing.T, resp *dns.Msg) { set(resp.Ns[0].(*dns.SOA)) }
	}
	tests := []struct {
		name   string
		mutate func(t *testing.T, resp *dns.Msg)
		ok     bool
	}{
		{name: "accepts the zone's SOA record with the smaller of its TTL and MINIMUM", mutate: func(*testing.T, *dns.Msg) {}, ok: true},
		{name: "accepts the owner in another case", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Name = "EXAMPLE.Test." }, ok: true},
		{name: "rejects the other rcode", mutate: nil},
		{name: "rejects a record in the answer section", mutate: func(t *testing.T, resp *dns.Msg) {
			resp.Answer = append(resp.Answer, mustRR(t, "nope.example.test. 300 IN A 192.0.2.1"))
		}},
		{name: "rejects an empty authority section", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns = nil }},
		{name: "rejects an NS record next to the SOA record", mutate: func(t *testing.T, resp *dns.Msg) {
			resp.Ns = append(resp.Ns, mustRR(t, "example.test. 300 IN NS ns1.example.test."))
		}},
		{name: "rejects an NS record instead of the SOA record", mutate: func(t *testing.T, resp *dns.Msg) {
			resp.Ns = []dns.RR{mustRR(t, "example.test. 300 IN NS ns1.example.test.")}
		}},
		{name: "rejects an SOA record in class CH", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Class = dns.ClassCHAOS }},
		{name: "rejects an SOA record owned by the question name", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Name = "nope.example.test." }},
		{name: "rejects another MNAME", mutate: soaField(func(soa *dns.SOA) { soa.Ns = "ns2.example.test." })},
		{name: "rejects another RNAME", mutate: soaField(func(soa *dns.SOA) { soa.Mbox = "hostmaster.example.test." })},
		{name: "rejects another serial", mutate: soaField(func(soa *dns.SOA) { soa.Serial++ })},
		{name: "rejects another refresh", mutate: soaField(func(soa *dns.SOA) { soa.Refresh++ })},
		{name: "rejects another retry", mutate: soaField(func(soa *dns.SOA) { soa.Retry++ })},
		{name: "rejects another expire", mutate: soaField(func(soa *dns.SOA) { soa.Expire++ })},
		{name: "rejects another minimum", mutate: soaField(func(soa *dns.SOA) { soa.Minttl++ })},
		{name: "rejects a TTL of 60 where the smaller value is 300", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Ttl = 60 }},
		{name: "rejects a TTL of 0", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Ttl = 0 }},
		{name: "rejects a TTL above the smaller value", mutate: func(_ *testing.T, resp *dns.Msg) { resp.Ns[0].Header().Ttl = 301 }},
		{name: "rejects a record in the additional section", mutate: func(t *testing.T, resp *dns.Msg) {
			resp.Extra = append(resp.Extra, mustRR(t, "ns1.example.test. 300 IN A 192.0.2.10"))
		}},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					resp := testReply(t, "NoPe.example.test.", dns.TypeA, c.rcode, nil, []string{testSOA}, nil)
					if tt.mutate == nil {
						resp.Rcode = c.otherRcode
					} else {
						tt.mutate(t, resp)
					}
					assertCheck(t, c.check(zoneSOA, resp), tt.ok)
				})
			}
		})
	}
}

// testTarget is the target of the example zone of the spec, example.test with two name servers.
func testTarget() *target {
	return &target{
		domain:      "example.test",
		nameServers: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")},
		email:       "admin@example.test",
		rname:       "admin.example.test.",
	}
}

func TestReferenceSOA(t *testing.T) {
	soaOf := func(owner, mname, rname string) string {
		return owner + " 300 IN SOA " + mname + " " + rname + " 2024072600 900 900 1800 300"
	}
	tests := []struct {
		name   string
		qname  string
		rcode  int
		answer []string
		mutate func(resp *dns.Msg)
		ok     bool
	}{
		{name: "accepts the zone's SOA record", answer: []string{testSOA}, ok: true},
		{name: "accepts a question in mixed case answered by its owner as asked", qname: "ExAmPlE.test.", answer: []string{soaOf("ExAmPlE.test.", "ns1.example.test.", "admin.example.test.")}, ok: true},
		{name: "accepts the MNAME in another case", answer: []string{soaOf("example.test.", "NS1.Example.Test.", "admin.example.test.")}, ok: true},
		{name: "rejects another rcode", rcode: dns.RcodeServerFailure, answer: []string{testSOA}},
		{name: "rejects an empty answer", answer: nil},
		{name: "rejects two SOA records", answer: []string{testSOA, testSOA}},
		{name: "rejects a record of another type in the answer", answer: []string{testSOA, "example.test. 300 IN NS ns1.example.test."}},
		{name: "rejects an SOA record in class CH", answer: []string{"example.test. 300 CH SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"}},
		{name: "rejects an SOA record owned by another name", answer: []string{soaOf("www.example.test.", "ns1.example.test.", "admin.example.test.")}},
		{name: "rejects the owner in another case than asked", answer: []string{soaOf("EXAMPLE.Test.", "ns1.example.test.", "admin.example.test.")}},
		{name: "rejects another MNAME", answer: []string{soaOf("example.test.", "ns2.example.test.", "admin.example.test.")}},
		{name: "rejects another RNAME", answer: []string{soaOf("example.test.", "ns1.example.test.", "hostmaster.example.test.")}},
		{name: "rejects AA clear", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.Authoritative = false }},
		{name: "rejects RA set", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.RecursionAvailable = true }},
		{name: "rejects AD set", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.AuthenticatedData = true }},
		{name: "rejects CD set", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.CheckingDisabled = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qname := cmp.Or(tt.qname, "example.test.")
			resp := testReply(t, qname, dns.TypeSOA, tt.rcode, tt.answer, nil, nil)
			if tt.mutate != nil {
				tt.mutate(resp)
			}
			soa, err := referenceSOA(testTarget(), resp)
			assertCheck(t, err, tt.ok)
			if tt.ok && soa != resp.Answer[0] {
				t.Errorf("referenceSOA returned %v, want the answer record %v", soa, resp.Answer[0])
			}
		})
	}
}

func TestCheckProbeCases(t *testing.T) {
	tg := testTarget()
	tg.delegations = []targetDelegation{{cut: "e2e-12345678.10-11-12-13.example.test.", nameServers: []string{"ns.other.test."}}}
	tg.recordSets = []targetRecordSet{{owner: "e2e-87654321.10.11.12.13.example.test.", rrtype: dns.TypeTXT, ttl: 300}}
	tests := []struct {
		name    string
		label   string
		wantErr []string
	}{
		{name: "accepts generated names the zone file does not touch", label: "e2e-00000000"},
		{name: "rejects a generated name the zone file delegates", label: "e2e-12345678", wantErr: []string{"e2e-12345678.10-11-12-13.example.test.", `"dashed with random prefix"`, "reserved for the suite's probes", "delegates it or a name above it: e2e-12345678.10-11-12-13.example.test. NS"}},
		{name: "rejects a generated name the zone file declares a record at", label: "e2e-87654321", wantErr: []string{"e2e-87654321.10.11.12.13.example.test.", `"dotted with random prefix"`, "reserved for the suite's probes", "declares e2e-87654321.10.11.12.13.example.test. TXT there"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkProbeCases(tg, publicResolverCases(tg, func() string { return tt.label }))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("checkProbeCases refused the cases: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkProbeCases accepted the cases, want an error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestCheckNegativeReplyTTLIsTheSmallerOfTheZoneTTLAndMinimum(t *testing.T) {
	tests := []struct {
		name    string
		zoneSOA string
		ttl     uint32
		ok      bool
	}{
		{name: "accepts MINIMUM when it is smaller than the TTL", zoneSOA: "example.test. 3600 IN SOA ns1.example.test. admin.example.test. 1 900 900 1800 300", ttl: 300, ok: true},
		{name: "rejects the TTL when MINIMUM is smaller", zoneSOA: "example.test. 3600 IN SOA ns1.example.test. admin.example.test. 1 900 900 1800 300", ttl: 3600},
		{name: "accepts the TTL when it is smaller than MINIMUM", zoneSOA: "example.test. 120 IN SOA ns1.example.test. admin.example.test. 1 900 900 1800 300", ttl: 120, ok: true},
		{name: "rejects MINIMUM when the TTL is smaller", zoneSOA: "example.test. 120 IN SOA ns1.example.test. admin.example.test. 1 900 900 1800 300", ttl: 300},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zoneSOA := mustRR(t, tt.zoneSOA).(*dns.SOA)
			negative := dns.Copy(zoneSOA)
			negative.Header().Ttl = tt.ttl
			resp := testReply(t, "nope.example.test.", dns.TypeA, dns.RcodeSuccess, nil, nil, nil)
			resp.Ns = []dns.RR{negative}
			assertCheck(t, checkNoData(zoneSOA, resp), tt.ok)
		})
	}
}

func assertCheck(t *testing.T, err error, ok bool) {
	t.Helper()
	if ok && err != nil {
		t.Errorf("check rejected the reply: %v", err)
	}
	if !ok && err == nil {
		t.Error("check accepted the reply, want it rejected")
	}
}

// testRecordSet builds a record set as the loader does, from records in zone file syntax with absolute names.
func testRecordSet(t *testing.T, records ...string) targetRecordSet {
	t.Helper()
	var set targetRecordSet
	for _, record := range records {
		rr, err := comparableRecord(mustRR(t, record))
		if err != nil {
			t.Fatal(err)
		}
		hdr := rr.Header()
		set.owner, set.rrtype, set.ttl = hdr.Name, hdr.Rrtype, hdr.Ttl
		set.records = append(set.records, rr)
	}
	return set
}

func TestCheckRecordSet(t *testing.T) {
	set := testRecordSet(t, "example.test. 300 IN MX 10 mail.other.test.", "example.test. 300 IN MX 20 www.example.test.")
	const mx10 = "ExAmPlE.test. 300 IN MX 10 mail.other.test."
	const mx20 = "ExAmPlE.test. 300 IN MX 20 www.example.test."
	tests := []struct {
		name       string
		answer     []string
		authority  []string
		additional []string
		ok         bool
	}{
		{name: "accepts the records in the declared order", answer: []string{mx10, mx20}, ok: true},
		{name: "accepts the records in another order", answer: []string{mx20, mx10}, ok: true},
		{name: "accepts targets in another case", answer: []string{"ExAmPlE.test. 300 IN MX 10 MAIL.Other.Test.", mx20}, ok: true},
		{name: "rejects an empty answer", answer: nil},
		{name: "rejects a missing record", answer: []string{mx10}},
		{name: "rejects a duplicated record in place of another", answer: []string{mx10, mx10}},
		{name: "rejects an additional record of the type", answer: []string{mx10, mx20, "ExAmPlE.test. 300 IN MX 30 other.test."}},
		{name: "rejects a record of another type", answer: []string{mx10, mx20, "ExAmPlE.test. 300 IN A 192.0.2.10"}},
		{name: "rejects a record in class CH", answer: []string{mx10, "ExAmPlE.test. 300 CH MX 20 www.example.test."}},
		{name: "rejects a record owned by another name", answer: []string{mx10, "www.example.test. 300 IN MX 20 www.example.test."}},
		{name: "rejects a record with another TTL", answer: []string{mx10, "ExAmPlE.test. 299 IN MX 20 www.example.test."}},
		{name: "rejects another preference", answer: []string{mx10, "ExAmPlE.test. 300 IN MX 30 www.example.test."}},
		{name: "rejects another exchange", answer: []string{mx10, "ExAmPlE.test. 300 IN MX 20 mail.example.test."}},
		{name: "rejects a record in the authority section", answer: []string{mx10, mx20}, authority: []string{testSOA}},
		{name: "rejects a record in the additional section", answer: []string{mx10, mx20}, additional: []string{"www.example.test. 300 IN A 192.0.2.80"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "ExAmPlE.test.", dns.TypeMX, dns.RcodeSuccess, tt.answer, tt.authority, tt.additional)
			assertCheck(t, checkRecordSet(set, resp), tt.ok)
		})
	}
}

func TestCheckRecordSetComparesEveryField(t *testing.T) {
	tests := []struct {
		rrtype    uint16
		declared  string
		same      []string
		different []string
	}{
		{rrtype: dns.TypeA, declared: "192.0.2.10", same: []string{"192.0.2.10"}, different: []string{"192.0.2.11"}},
		{rrtype: dns.TypeAAAA, declared: "2001:db8::10", same: []string{"2001:DB8:0::10"}, different: []string{"2001:db8::11"}},
		{rrtype: dns.TypeTXT, declared: `"one" "two"`, same: []string{`"one" "two"`, "one two"}, different: []string{`"one two"`, `"two" "one"`, `"one"`, `"one" "two" "three"`, `"one" "Two"`}},
		{rrtype: dns.TypeTXT, declared: `"v=DMARC1; p=none"`, same: []string{`"v=DMARC1; p=none"`}, different: []string{`"v=DMARC1;" "p=none"`}},
		{rrtype: dns.TypeMX, declared: "10 mail.example.net.", same: []string{"10 MAIL.Example.NET."}, different: []string{"20 mail.example.net.", "10 mx.example.net."}},
		{rrtype: dns.TypeSRV, declared: "0 5 443 target.example.net.", same: []string{"0 5 443 TARGET.example.net."}, different: []string{"1 5 443 target.example.net.", "0 6 443 target.example.net.", "0 5 444 target.example.net.", "0 5 443 other.example.net."}},
		{rrtype: dns.TypeCNAME, declared: "target.example.net.", same: []string{"Target.Example.Net."}, different: []string{"other.example.net."}},
		{rrtype: dns.TypeCAA, declared: `0 issue ";"`, same: []string{`0 issue ";"`}, different: []string{`128 issue ";"`, `0 issuewild ";"`, `0 issue "letsencrypt.org"`}},
	}

	for _, tt := range tests {
		typeName := dns.Type(tt.rrtype).String()
		set := testRecordSet(t, "name.example.test. 300 IN "+typeName+" "+tt.declared)
		check := func(t *testing.T, rdata string, ok bool) {
			resp := testReply(t, "name.example.test.", tt.rrtype, dns.RcodeSuccess, []string{"name.example.test. 300 IN " + typeName + " " + rdata}, nil, nil)
			assertCheck(t, checkRecordSet(set, resp), ok)
		}
		for _, rdata := range tt.same {
			t.Run(fmt.Sprintf("%s %s accepts %s", typeName, tt.declared, rdata), func(t *testing.T) { check(t, rdata, true) })
		}
		for _, rdata := range tt.different {
			t.Run(fmt.Sprintf("%s %s rejects %s", typeName, tt.declared, rdata), func(t *testing.T) { check(t, rdata, false) })
		}
	}
}

func TestCheckHINFO(t *testing.T) {
	const qname = "10-11-12-13.example.test."
	const hinfo = qname + ` 3600 IN HINFO "RFC8482" ""`
	tests := []struct {
		name       string
		answer     []string
		authority  []string
		additional []string
		ok         bool
	}{
		{name: "accepts a well-formed reply", answer: []string{hinfo}, ok: true},
		{name: "accepts the owner in another case", answer: []string{`10-11-12-13.EXAMPLE.test. 3600 IN HINFO "RFC8482" ""`}, ok: true},
		{name: "rejects an empty answer", answer: nil},
		{name: "rejects two HINFO records", answer: []string{hinfo, hinfo}},
		{name: "rejects a record of another type", answer: []string{qname + " 3600 IN A 10.11.12.13"}},
		{name: "rejects a record in class CH", answer: []string{qname + ` 3600 CH HINFO "RFC8482" ""`}},
		{name: "rejects a record owned by another name", answer: []string{`example.test. 3600 IN HINFO "RFC8482" ""`}},
		{name: "rejects another CPU", answer: []string{qname + ` 3600 IN HINFO "RFC8484" ""`}},
		{name: "rejects an OS that is not empty", answer: []string{qname + ` 3600 IN HINFO "RFC8482" "Linux"`}},
		{name: "rejects another TTL", answer: []string{qname + ` 300 IN HINFO "RFC8482" ""`}},
		{name: "rejects a record in the authority section", answer: []string{hinfo}, authority: []string{testSOA}},
		{name: "rejects a record in the additional section", answer: []string{hinfo}, additional: []string{"ns1.example.test. 300 IN A 192.0.2.10"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, qname, dns.TypeANY, dns.RcodeSuccess, tt.answer, tt.authority, tt.additional)
			assertCheck(t, checkHINFO(resp), tt.ok)
		})
	}
}

func TestCheckNoRecords(t *testing.T) {
	tests := []struct {
		name       string
		answer     []string
		authority  []string
		additional []string
		ok         bool
	}{
		{name: "accepts a reply with the question only", ok: true},
		{name: "rejects a record in the answer section", answer: []string{"example.test. 300 IN TXT \"x\""}},
		{name: "rejects a record in the authority section", authority: []string{testSOA}},
		{name: "rejects a record in the additional section", additional: []string{"ns1.example.test. 300 IN A 192.0.2.10"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "example.test.", dns.TypeTXT, dns.RcodeRefused, tt.answer, tt.authority, tt.additional)
			assertCheck(t, checkNoRecords(resp), tt.ok)
		})
	}
}

func TestCheckReplyOnPath(t *testing.T) {
	type flags struct{ aa, ra, ad, cd bool }
	const asked = "ExAmPlE.test."
	tests := []struct {
		name   string
		tc     dnsCase
		path   dnsPath
		resp   flags
		answer []string
		ok     bool
	}{
		{name: "accepts AA set where the case requires it", tc: dnsCase{authoritative: true}, resp: flags{aa: true}, ok: true},
		{name: "rejects AA clear where the case requires it set", tc: dnsCase{authoritative: true}},
		{name: "accepts AA clear where the case requires it clear", tc: dnsCase{nonAuthoritative: true}, ok: true},
		{name: "rejects AA set where the case requires it clear", tc: dnsCase{nonAuthoritative: true}, resp: flags{aa: true}},
		{name: "accepts AA either way where the case requires nothing", resp: flags{aa: true}, ok: true},
		{name: "rejects RA from a name server", resp: flags{ra: true}},
		{name: "rejects AD from a name server", resp: flags{ad: true}},
		{name: "rejects CD from a name server", resp: flags{cd: true}},
		{name: "accepts RA, AD and CD from a public resolver", path: throughResolver, resp: flags{ra: true, ad: true, cd: true}, ok: true},
		{name: "accepts an answer from a name server owned by the question name as asked", answer: []string{asked + " 300 IN A 192.0.2.10"}, ok: true},
		{name: "rejects an answer from a name server owned by the question name in another case", answer: []string{"example.test. 300 IN A 192.0.2.10"}},
		{name: "rejects an answer from a name server of which one record is owned in another case", answer: []string{asked + " 300 IN A 192.0.2.10", "EXAMPLE.TEST. 300 IN A 192.0.2.11"}},
		{name: "accepts an answer through a resolver owned by the question name in another case", path: throughResolver, answer: []string{"example.test. 300 IN A 192.0.2.10"}, ok: true},
		{name: "rejects an answer through a resolver owned by another name", path: throughResolver, answer: []string{"www.example.test. 300 IN A 192.0.2.10"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, asked, dns.TypeA, dns.RcodeSuccess, tt.answer, nil, nil)
			resp.Authoritative, resp.RecursionAvailable, resp.AuthenticatedData, resp.CheckingDisabled = tt.resp.aa, tt.resp.ra, tt.resp.ad, tt.resp.cd
			assertCheck(t, checkReplyOnPath(tt.tc, tt.path, resp), tt.ok)
		})
	}
}

func TestCheckReplyHeader(t *testing.T) {
	tests := []struct {
		name      string
		recursion bool
		mutate    func(resp *dns.Msg)
		ok        bool
	}{
		{name: "accepts a reply to a query without RD", mutate: func(*dns.Msg) {}, ok: true},
		{name: "accepts a reply to a query with RD that keeps it", recursion: true, mutate: func(resp *dns.Msg) { resp.RecursionDesired = true }, ok: true},
		{name: "rejects a message with the QR flag clear", mutate: func(resp *dns.Msg) { resp.Response = false }},
		{name: "rejects an opcode other than QUERY", mutate: func(resp *dns.Msg) { resp.Opcode = dns.OpcodeNotify }},
		{name: "rejects RD set in reply to a query without it", mutate: func(resp *dns.Msg) { resp.RecursionDesired = true }},
		{name: "rejects RD clear in reply to a query with it", recursion: true, mutate: func(resp *dns.Msg) { resp.RecursionDesired = false }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "example.test.", dns.TypeSOA, dns.RcodeSuccess, nil, nil, nil)
			resp.RecursionDesired = false
			tt.mutate(resp)
			q := dnsQuery{name: "example.test.", qtype: dns.TypeSOA, qclass: dns.ClassINET, recursion: tt.recursion}
			assertCheck(t, checkReplyHeader(q, resp), tt.ok)
		})
	}
}

func TestCheckQuestionEchoOfClass(t *testing.T) {
	resp := testReply(t, "example.test.", dns.TypeTXT, dns.RcodeRefused, nil, nil, nil)
	resp.Question[0].Qclass = dns.ClassCHAOS

	t.Run("accepts the class asked", func(t *testing.T) {
		assertCheck(t, checkQuestionEchoOfClass(resp, "example.test.", dns.TypeTXT, dns.ClassCHAOS), true)
	})
	t.Run("rejects another class", func(t *testing.T) {
		assertCheck(t, checkQuestionEchoOfClass(resp, "example.test.", dns.TypeTXT, dns.ClassINET), false)
	})
	t.Run("rejects a class other than IN where IN was asked", func(t *testing.T) {
		assertCheck(t, checkQuestionEcho(resp, "example.test.", dns.TypeTXT), false)
	})
}

func TestDNSCaseQuery(t *testing.T) {
	tc := dnsCase{qname: "example.test.", qtype: dns.TypeSOA, checkingDisabled: true}
	if got, want := tc.query(toNameServer), (dnsQuery{name: "example.test.", qtype: dns.TypeSOA, qclass: dns.ClassINET, checkingDisabled: true}); got != want {
		t.Errorf("query to a name server = %+v, want %+v", got, want)
	}
	tc.qclass = dns.ClassCHAOS
	if got, want := tc.query(throughResolver), (dnsQuery{name: "example.test.", qtype: dns.TypeSOA, qclass: dns.ClassCHAOS, recursion: true, checkingDisabled: true}); got != want {
		t.Errorf("query through a resolver = %+v, want %+v", got, want)
	}
}

func TestNameOfWireLength(t *testing.T) {
	for _, zone := range []string{"example.test.", "xip-staging.local-ip.sh.", "local-ip.sh"} {
		for _, octets := range []int{253, 254, 255} {
			t.Run(fmt.Sprintf("%d octets below %s", octets, zone), func(t *testing.T) {
				name := nameOfWireLength(zone, octets)

				buf := make([]byte, 512)
				got, err := dns.PackDomainName(name, buf, 0, nil, false)
				if err != nil {
					t.Fatalf("packing %q: %v", name, err)
				}
				if got != octets {
					t.Errorf("%q has %d octets in wire format, want %d", name, got, octets)
				}
				if !dns.IsSubDomain(dns.Fqdn(zone), name) {
					t.Errorf("%q is not below %s", name, zone)
				}
				for _, label := range dns.SplitDomainName(strings.TrimSuffix(name, dns.Fqdn(zone))) {
					if label == "" || len(label) > 63 || strings.Trim(label, "x") != "" {
						t.Errorf("label %q of %q is not 1 to 63 letters x", label, name)
					}
				}

				query := new(dns.Msg)
				query.SetQuestion(name, dns.TypeA)
				packed, err := query.Pack()
				if err != nil {
					t.Fatalf("packing a query for %q: %v", name, err)
				}
				var unpacked dns.Msg
				if err := unpacked.Unpack(packed); err != nil {
					t.Fatalf("unpacking a query for %q: %v", name, err)
				}
				if unpacked.Question[0].Name != name {
					t.Errorf("query round trip gives %q, want %q", unpacked.Question[0].Name, name)
				}
			})
		}
	}
}

// TestAuthoritativeCases holds the case list of each committed target to the flag rules of the zone: AA set on every answer from the zone, clear on every refusal, and NXDOMAIN only for a name too long to have a child.
func TestAuthoritativeCases(t *testing.T) {
	for _, configPath := range []string{"../fly.toml", "../fly.staging.toml"} {
		t.Run(configPath, func(t *testing.T) {
			tg, err := loadTarget(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cases := authoritativeCases(tg, nil)
			names := make(map[string]bool)
			for _, tc := range cases {
				q := tc.query(toNameServer)
				t.Logf("%-70s %s rcodes %v AA set %t AA clear %t CD %t", tc.name, q, tc.rcodes, tc.authoritative, tc.nonAuthoritative, tc.checkingDisabled)
				if names[tc.name] {
					t.Errorf("case name %q is used twice", tc.name)
				}
				names[tc.name] = true
				if tc.check == nil {
					t.Errorf("case %q has no check", tc.name)
				}
				if len(tc.rcodes) != 1 {
					t.Errorf("case %q accepts %d rcodes, want exactly one", tc.name, len(tc.rcodes))
					continue
				}
				switch tc.rcodes[0] {
				case dns.RcodeSuccess, dns.RcodeNameError:
					if !tc.authoritative || tc.nonAuthoritative {
						t.Errorf("case %q answers from the zone and does not require AA set", tc.name)
					}
				case dns.RcodeRefused:
					if tc.authoritative || !tc.nonAuthoritative {
						t.Errorf("case %q is a refusal and does not require AA clear", tc.name)
					}
				}
				buf := make([]byte, 512)
				octets, err := dns.PackDomainName(tc.qname, buf, 0, nil, false)
				if err != nil {
					t.Fatalf("case %q: packing %q: %v", tc.name, tc.qname, err)
				}
				if tooLong := octets > 253; tooLong != (tc.rcodes[0] == dns.RcodeNameError) {
					t.Errorf("case %q asks for a name of %d octets and expects %s", tc.name, octets, dns.RcodeToString[tc.rcodes[0]])
				}
			}

			for _, set := range tg.recordSets {
				label := set.owner + " " + dns.Type(set.rrtype).String()
				for _, name := range []string{"declared " + label, "mixed case declared " + label} {
					if !names[name] {
						t.Errorf("no case %q", name)
					}
				}
			}
		})
	}
}
