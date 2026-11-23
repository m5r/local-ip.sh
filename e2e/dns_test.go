package e2e

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
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

// serverUDPSize is the UDP payload size a name server of the target advertises in the OPT record of every reply to a query with one.
const serverUDPSize = 1232

// ednsOPT is the OPT record a query carries. The zero value sends none: no query of the suite advertises a size of 0.
type ednsOPT struct {
	udpSize uint16
	version uint8
}

// dnsQuery is one question, the header flags and the OPT record it is sent with, the transport it goes over and whether the reply is expected truncated.
type dnsQuery struct {
	name             string
	qtype            uint16
	qclass           uint16
	recursion        bool
	checkingDisabled bool
	tcp              bool
	edns             ednsOPT
	truncated        bool
	// followTruncation accepts a truncated reply, which the caller follows with the same question over TCP.
	followTruncation bool
}

func (q dnsQuery) String() string {
	s := fmt.Sprintf("%s %s %s", q.name, dns.Class(q.qclass), dns.Type(q.qtype))
	if q.edns != (ednsOPT{}) {
		s += fmt.Sprintf(" with EDNS version %d size %d", q.edns.version, q.edns.udpSize)
	}
	if q.tcp {
		s += " over TCP"
	}
	return s
}

// exchange sends one question to port 53 of the server.
func exchange(t *testing.T, server netip.Addr, q dnsQuery) (*dns.Msg, error) {
	t.Helper()
	return exchangeAt(t, netip.AddrPortFrom(server, 53), q)
}

// exchangeAt sends one question and returns the first response it gets. Only timeouts and network errors are retried; any decoded response is final whatever its rcode, so a wrong answer is never hidden by a retry. A response is returned together with an error when it does not echo the question or its TC flag is not the one the query expects: a truncated reply is only accepted where the query expects one or follows truncation itself.
func exchangeAt(t *testing.T, server netip.AddrPort, q dnsQuery) (*dns.Msg, error) {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(q.name, q.qtype)
	query.Question[0].Qclass = q.qclass
	query.RecursionDesired = q.recursion
	query.CheckingDisabled = q.checkingDisabled
	if q.edns != (ednsOPT{}) {
		query.SetEdns0(q.edns.udpSize, false)
		query.IsEdns0().SetVersion(q.edns.version)
	}

	client := &dns.Client{Net: "udp", Timeout: dnsAttemptTimeout}
	if q.tcp {
		client.Net = "tcp"
	}
	address := server.String()
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
			if err := checkTruncation(q, resp); err != nil {
				return resp, fmt.Errorf("response from %s for %s: %w", address, q, err)
			}
			return resp, nil
		}

		t.Logf("DNS attempt %d/%d to %s for %s failed after %s: %v", attempt, attempts, address, q, time.Since(started).Round(time.Millisecond), err)
		if !lostAttempt(q, err) {
			return nil, fmt.Errorf("querying %s for %s: %w", address, q, err)
		}
		lastErr = err
		if t.Context().Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("%w from %s for %s after %d attempt(s), last error: %w", errNoDNSResponse, address, q, made, lastErr)
}

// lostAttempt reports whether an attempt failed without a reply, as opposed to with one the client could not use. Over TCP that includes a connection the far side closes before a whole reply arrived: resolvers do so for some questions about names they have not cached, and a proxy does so while the service behind it starts, so it is a lost attempt like a UDP timeout.
func lostAttempt(q dnsQuery, err error) bool {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) {
		return true
	}
	return q.tcp && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))
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

// checkReplyHeader checks the header fields every reply to the query must have: the client matches a reply by its id alone, so a message that is no reply to a standard query, or one that does not copy the RD flag of the query, would otherwise pass.
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

func checkTruncation(q dnsQuery, resp *dns.Msg) error {
	switch {
	case resp.Truncated && !q.truncated && !q.followTruncation:
		return errors.New("reply is truncated (TC flag set), want it whole")
	case !resp.Truncated && q.truncated:
		return errors.New("TC flag is clear, want the reply truncated")
	}
	return nil
}

// checkReplyOPT checks the OPT record of a name server's reply against the query: none in reply to a query without one, and otherwise exactly one that advertises serverUDPSize, version 0, the DO flag of the query (always clear) and no options, whatever the rcode.
func checkReplyOPT(q dnsQuery, resp *dns.Msg) error {
	var opts []*dns.OPT
	for _, rr := range resp.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			opts = append(opts, opt)
		}
	}
	if q.edns == (ednsOPT{}) {
		if len(opts) != 0 {
			return fmt.Errorf("reply has %d OPT records, want none in reply to a query without one", len(opts))
		}
		return nil
	}
	if len(opts) != 1 {
		return fmt.Errorf("reply has %d OPT records, want exactly one in reply to a query with one", len(opts))
	}
	opt := opts[0]
	var problems []error
	if opt.Hdr.Name != "." {
		problems = append(problems, fmt.Errorf("OPT record is owned by %q, want the root", opt.Hdr.Name))
	}
	if opt.UDPSize() != serverUDPSize {
		problems = append(problems, fmt.Errorf("OPT UDP size = %d, want %d", opt.UDPSize(), serverUDPSize))
	}
	if opt.Version() != 0 {
		problems = append(problems, fmt.Errorf("OPT version = %d, want 0", opt.Version()))
	}
	if opt.Do() {
		problems = append(problems, errors.New("OPT DO flag is set, want it clear as in the query"))
	}
	if len(opt.Option) != 0 {
		problems = append(problems, fmt.Errorf("OPT record has %d options, want none", len(opt.Option)))
	}
	return errors.Join(problems...)
}

// withoutOPT is a copy of the reply without its OPT records, so the checks of the sections, written for replies without EDNS, see the same content whether the query carried one or not.
func withoutOPT(resp *dns.Msg) *dns.Msg {
	content := resp.Copy()
	content.Extra = slices.DeleteFunc(content.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeOPT })
	return content
}

// rcodeName names an rcode; the library's table names 16 after its meaning in a TSIG record, BADSIG, but in a reply's header and OPT record it is BADVERS.
func rcodeName(rcode int) string {
	if rcode == dns.RcodeBadVers {
		return "BADVERS"
	}
	return dns.RcodeToString[rcode]
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
	tcp              bool
	edns             ednsOPT
	truncated        bool
	rcodes           []int
	authoritative    bool
	nonAuthoritative bool
	// fromZoneFile marks a case generated from a declaration of the zone file, whose name is declared by construction.
	fromZoneFile bool
	// check sees the reply without its OPT record, which is checked on its own.
	check func(t *testing.T, resp *dns.Msg)
	// checkTruncated, where set, makes the case follow truncation as a resolver does: a truncated reply over UDP is held to checkTruncated and the question is asked again over TCP, whose reply is held to check. It sees the truncated reply without its OPT record.
	checkTruncated func(t *testing.T, resp *dns.Msg)
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
	q := dnsQuery{name: tc.qname, qtype: tc.qtype, qclass: tc.qclass, recursion: path == throughResolver, checkingDisabled: tc.checkingDisabled, tcp: tc.tcp, edns: tc.edns, truncated: tc.truncated, followTruncation: tc.checkTruncated != nil}
	if q.qclass == 0 {
		q.qclass = dns.ClassINET
	}
	return q
}

// checkReplyOnPath checks the AA flag a case asks for, the owners of the answer records and, on a reply straight from a name server, the flags an authoritative-only server without DNSSEC never sets: it offers no recursion, validates nothing and so must not echo CD.
// A name server owns its answer records by the question name exactly as asked, which is also what keeps the size of a reply the same whatever the case of the question; a resolver may spell the owner its own way.
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

// runDNSCasesUntilSilent runs the cases as subtests until one gets no response at all over UDP, and reports whether that happened and how many cases were left unrun. A question over TCP that gets no response fails its case alone: a server without TCP still answers every other case.
func runDNSCasesUntilSilent(t *testing.T, server netip.Addr, path dnsPath, cases []dnsCase) (notRun int, silent bool) {
	t.Helper()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, truncated, q, err := askCase(t, netip.AddrPortFrom(server, 53), path, tc)
			if truncated != nil {
				if path == toNameServer {
					if err := checkReplyOPT(tc.query(path), truncated); err != nil {
						t.Errorf("truncated reply over UDP: %v", err)
					}
				}
				tc.checkTruncated(t, withoutOPT(truncated))
				if t.Failed() || err != nil {
					t.Logf("truncated reply over UDP from %s:\n%s", server, truncated)
				}
			}
			if err != nil {
				silent = errors.Is(err, errNoDNSResponse) && !q.tcp
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
					names[i] = rcodeName(rcode)
				}
				t.Errorf("rcode = %s, want one of %v", rcodeName(resp.Rcode), names)
			}
			if path == toNameServer {
				if err := checkReplyOPT(q, resp); err != nil {
					t.Error(err)
				}
			}
			content := withoutOPT(resp)
			if err := checkReplyOnPath(tc, path, content); err != nil {
				t.Error(err)
			}
			if tc.check != nil {
				tc.check(t, content)
			}
		})
		if silent {
			return len(cases) - i - 1, true
		}
	}
	return 0, false
}

// askCase sends the question of the case and returns the reply to check, the query that got it, and the truncated reply over UDP it followed, if any. A case with checkTruncated that gets a truncated reply asks again over TCP within the same case, as a resolver does; that question does not follow truncation, so a truncated reply over TCP is an error.
func askCase(t *testing.T, server netip.AddrPort, path dnsPath, tc dnsCase) (resp, truncated *dns.Msg, q dnsQuery, err error) {
	t.Helper()
	q = tc.query(path)
	resp, err = exchangeAt(t, server, q)
	if err != nil || !q.followTruncation || !resp.Truncated {
		return resp, nil, q, err
	}
	truncated = resp
	q.tcp, q.followTruncation = true, false
	resp, err = exchangeAt(t, server, q)
	return resp, truncated, q, err
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

// expectNS checks the NS targets of an answer through a resolver, in any order; whether a resolver adds the name servers' addresses is its own choice, so the other sections are not held to anything.
func expectNS(hosts []string) func(*testing.T, *dns.Msg) {
	return func(t *testing.T, resp *dns.Msg) {
		t.Helper()
		records, err := recordsOfType[*dns.NS](resp.Answer, resp.Question[0].Name, dns.TypeNS)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, len(records))
		for i, record := range records {
			got[i] = dns.CanonicalName(record.Ns)
		}
		slices.Sort(got)
		want := slices.Sorted(slices.Values(hosts))
		if !slices.Equal(got, want) {
			t.Errorf("NS targets = %v, want %v (any order)", got, want)
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

// checkNegative compares the SOA record of a negative answer with zoneSOA, the zone file's SOA record: RFC 2308 section 3 asks for that record with a TTL of the smaller of its own TTL and its MINIMUM field.
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

// checkApexSOA holds an answer to the zone's SOA question to the zone file's SOA record, every field and the TTL.
func checkApexSOA(tg *target, resp *dns.Msg) error {
	zone := tg.zone()
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("answered %s for %s SOA, want NOERROR", dns.RcodeToString[resp.Rcode], zone)
	}
	records, err := recordsOfType[*dns.SOA](resp.Answer, zone, dns.TypeSOA)
	if err != nil {
		return fmt.Errorf("answer for %s SOA: %w", zone, err)
	}
	if len(records) != 1 {
		return fmt.Errorf("returned %d SOA records for %s, want exactly 1", len(records), zone)
	}
	if err := sameRecord(records[0], tg.soa); err != nil {
		return fmt.Errorf("SOA record of the answer: %w", err)
	}
	return nil
}

// sameRecord holds a record of a reply to the declared one: type, class IN, owner in any case, TTL and every field of the RDATA.
func sameRecord(rr, declared dns.RR) error {
	hdr, want := rr.Header(), declared.Header()
	if hdr.Rrtype != want.Rrtype {
		return fmt.Errorf("record %q is not of type %s", rr, dns.Type(want.Rrtype))
	}
	if hdr.Class != dns.ClassINET {
		return fmt.Errorf("record %q has class %s, want IN", rr, dns.Class(hdr.Class))
	}
	if !strings.EqualFold(hdr.Name, want.Name) {
		return fmt.Errorf("record %q is owned by %q, want %q", rr, hdr.Name, want.Name)
	}
	if hdr.Ttl != want.Ttl {
		return fmt.Errorf("record %q has TTL %d, want the declared %d", rr, hdr.Ttl, want.Ttl)
	}
	got, err := rdataFields(rr)
	if err != nil {
		return err
	}
	wantFields, err := rdataFields(declared)
	if err != nil {
		return fmt.Errorf("declared record: %w", err)
	}
	if got != wantFields {
		return fmt.Errorf("record has %s, want the declared %s", got, wantFields)
	}
	return nil
}

func expectApexSOA(tg *target) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkApexSOA(tg, resp) })
}

// checkRecordSet checks an answer that carries the declared record set, owned by the question name.
func checkRecordSet(set targetRecordSet, resp *dns.Msg) error {
	got, want, err := answerAndDeclaredRDATA(set, resp, func(ttl uint32) bool { return ttl == set.ttl })
	if err != nil {
		return err
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("answer RDATA = %q, want %q (any order)", got, want)
	}
	return nil
}

// checkCachedRecordSet checks an answer through a resolver that carries the declared record set: a resolver counts the TTL down while the set sits in its cache.
func checkCachedRecordSet(set targetRecordSet, resp *dns.Msg) error {
	got, want, err := answerAndDeclaredRDATA(set, resp, func(ttl uint32) bool { return ttl <= set.ttl })
	if err != nil {
		return err
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("answer RDATA = %q, want %q (any order)", got, want)
	}
	return nil
}

// checkPartOfRecordSet checks a truncated answer for the declared record set: the records that are there must be declared ones, each at most once, and at least one declared record must be missing, since a server truncates only when the whole set does not fit.
func checkPartOfRecordSet(set targetRecordSet, resp *dns.Msg) error {
	got, want, err := answerAndDeclaredRDATA(set, resp, func(ttl uint32) bool { return ttl == set.ttl })
	if err != nil {
		return err
	}
	remaining := slices.Clone(want)
	for _, fields := range got {
		i := slices.Index(remaining, fields)
		if i < 0 {
			return fmt.Errorf("answer record with RDATA %s is not one of the declared %q, or appears twice", fields, want)
		}
		remaining = slices.Delete(remaining, i, i+1)
	}
	if len(remaining) == 0 {
		return fmt.Errorf("truncated answer carries all %d declared records, want some of them missing", len(want))
	}
	return nil
}

// answerAndDeclaredRDATA checks every answer record against the declared set's owner, type, class and a TTL that ttlOK accepts, requires the other sections empty, and returns the RDATA of the answer and of the declared set, each sorted.
func answerAndDeclaredRDATA(set targetRecordSet, resp *dns.Msg, ttlOK func(uint32) bool) (got, want []string, err error) {
	got, want, err = answerRDATA(set, resp, ttlOK)
	if err != nil {
		return nil, nil, err
	}
	if len(resp.Ns) != 0 {
		return nil, nil, fmt.Errorf("authority section has %d records, want none", len(resp.Ns))
	}
	if len(resp.Extra) != 0 {
		return nil, nil, fmt.Errorf("additional section has %d records, want none", len(resp.Extra))
	}
	return got, want, nil
}

// answerRDATA checks every answer record against the declared set's owner, type, class and a TTL that ttlOK accepts, and returns the RDATA of the answer and of the declared set, each sorted.
func answerRDATA(set targetRecordSet, resp *dns.Msg, ttlOK func(uint32) bool) (got, want []string, err error) {
	if len(resp.Question) != 1 {
		return nil, nil, fmt.Errorf("question section has %d entries, want 1", len(resp.Question))
	}
	qname := resp.Question[0].Name
	got = make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		hdr := rr.Header()
		if hdr.Rrtype != set.rrtype {
			return nil, nil, fmt.Errorf("answer record %q is not of type %s", rr, dns.Type(set.rrtype))
		}
		if hdr.Class != dns.ClassINET {
			return nil, nil, fmt.Errorf("answer record %q has class %s, want IN", rr, dns.Class(hdr.Class))
		}
		if !strings.EqualFold(hdr.Name, qname) {
			return nil, nil, fmt.Errorf("answer record %q is owned by %q, want the question name %q", rr, hdr.Name, qname)
		}
		if !ttlOK(hdr.Ttl) {
			return nil, nil, fmt.Errorf("answer record %q has TTL %d, want the declared %d", rr, hdr.Ttl, set.ttl)
		}
		fields, err := rdataFields(rr)
		if err != nil {
			return nil, nil, err
		}
		got = append(got, fields)
	}
	want = make([]string, 0, len(set.records))
	for _, rr := range set.records {
		fields, err := rdataFields(rr)
		if err != nil {
			return nil, nil, fmt.Errorf("declared record: %w", err)
		}
		want = append(want, fields)
	}
	slices.Sort(got)
	slices.Sort(want)
	return got, want, nil
}

// checkApexNS checks the answer to NS at the apex: the zone file's NS records of the apex in the answer, in any order, nothing in the authority section, and in the additional section exactly apexNSAdditional, in its order, so that a missing, an extra or a misplaced address shows.
func checkApexNS(tg *target, resp *dns.Msg) error {
	got, want, err := answerRDATA(tg.apexNS, resp, func(ttl uint32) bool { return ttl == tg.apexNS.ttl })
	if err != nil {
		return err
	}
	if !slices.Equal(got, want) {
		return fmt.Errorf("answer RDATA = %q, want %q (any order)", got, want)
	}
	if len(resp.Ns) != 0 {
		return fmt.Errorf("authority section has %d records, want none", len(resp.Ns))
	}
	if len(resp.Extra) != len(tg.apexNSAdditional) {
		return fmt.Errorf("additional section has %d records, want the %d address records of the name servers inside the zone, %q", len(resp.Extra), len(tg.apexNSAdditional), tg.apexNSAdditional)
	}
	for i, rr := range resp.Extra {
		if err := sameRecord(rr, tg.apexNSAdditional[i]); err != nil {
			return fmt.Errorf("additional record %d of %q: %w", i+1, tg.apexNSAdditional, err)
		}
	}
	return nil
}

func expectApexNS(tg *target) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkApexNS(tg, resp) })
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
	case *dns.SOA:
		return fmt.Sprintf("MNAME %s, RNAME %s, serial %d, refresh %d, retry %d, expire %d, minimum %d", dns.CanonicalName(record.Ns), dns.CanonicalName(record.Mbox), record.Serial, record.Refresh, record.Retry, record.Expire, record.Minttl), nil
	}
	return "", fmt.Errorf("record %q has a type the suite cannot compare", rr)
}

// addressTTL is the TTL the server gives the address a name carries, the one record it computes from the name alone.
const addressTTL uint32 = 86400

// checkTTL requires an answer from a name server and holds every answer record to the TTL given: a name server gives each record the TTL it holds, where a resolver would count it down.
func checkTTL(ttl uint32, resp *dns.Msg) error {
	if len(resp.Answer) == 0 {
		return fmt.Errorf("answer section is empty, want records with TTL %d", ttl)
	}
	for _, rr := range resp.Answer {
		if got := rr.Header().Ttl; got != ttl {
			return fmt.Errorf("answer record %q has TTL %d, want %d", rr, got, ttl)
		}
	}
	return nil
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

func expectCachedRecordSet(set targetRecordSet) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkCachedRecordSet(set, resp) })
}

func expectPartOfRecordSet(set targetRecordSet) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkPartOfRecordSet(set, resp) })
}

func expectTTL(ttl uint32) func(*testing.T, *dns.Msg) {
	return asCheck(func(resp *dns.Msg) error { return checkTTL(ttl, resp) })
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
	for _, server := range tg.dnsServers {
		t.Run(server.String(), func(t *testing.T) {
			runDNSCases(t, server, toNameServer, authoritativeCases(tg))
		})
	}
}

// authoritativeCases are the cases every name server of the target must answer from its zone; the negative answers carry the zone file's SOA record.
func authoritativeCases(tg *target) []dnsCase {
	zone := tg.zone()
	want := netip.MustParseAddr("10.11.12.13")
	noError := []int{dns.RcodeSuccess}
	refused := []int{dns.RcodeRefused}
	nameError := []int{dns.RcodeNameError}
	noData := expectNoData(tg.soa)

	cases := []dnsCase{
		{name: "dashed", qname: "10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed with prefix", qname: "app.10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted", qname: "10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted with prefix", qname: "foo.bar.10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed with labels after the address", qname: "10-11-12-13.app." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted with labels after the address", qname: "10.11.12.13.app." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed after a name in the label", qname: "app-10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed before a name in the label", qname: "10-11-12-13-app." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed between names in the label", qname: "a-10-11-12-13-b." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dotted after a name and a hyphen", qname: "app-10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "mixed case dashed after a name in the label", qname: alternateCase("app-10-11-12-13." + zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
		{name: "dashed after a name in the label AAAA", qname: "app-10-11-12-13." + zone, qtype: dns.TypeAAAA, rcodes: noError, authoritative: true, check: noData},
		{name: "three numbers after a name in the label", qname: "app-10-11-12." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
		{name: "leading zero", qname: "10-11-12-013." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: noData},
	}
	cases = append(cases,
		dnsCase{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: expectApexNS(tg)},
		dnsCase{name: "mixed case apex NS", qname: alternateCase(zone), qtype: dns.TypeNS, rcodes: noError, authoritative: true, check: expectApexNS(tg)},
		dnsCase{name: "apex SOA", qname: zone, qtype: dns.TypeSOA, rcodes: noError, authoritative: true, check: expectApexSOA(tg)},
		dnsCase{name: "CD flag", qname: zone, qtype: dns.TypeSOA, checkingDisabled: true, rcodes: noError, authoritative: true, check: expectApexSOA(tg)},
		dnsCase{name: "dashed AAAA", qname: "10-11-12-13." + zone, qtype: dns.TypeAAAA, rcodes: noError, authoritative: true, check: noData},
	)
	// The TTL of the address a name carries has a case of its own, so that a server that gives another TTL fails this case alone and the address cases still run; the TTL of every declared record is checked with its record set.
	cases = append(cases,
		dnsCase{name: "dashed TTL", qname: "10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectTTL(addressTTL)},
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
		dnsCase{name: "name of 254 octets is too long to have a child", qname: nameOfWireLength(zone, 254), qtype: dns.TypeA, rcodes: nameError, authoritative: true, check: expectNameError(tg.soa)},
		dnsCase{name: "name of 255 octets is too long to have a child", qname: nameOfWireLength(zone, 255), qtype: dns.TypeA, rcodes: nameError, authoritative: true, check: expectNameError(tg.soa)},
	)
	for _, qtype := range []uint16{dns.TypeDS, dns.TypeDNSKEY, 65280} {
		cases = append(cases, dnsCase{name: "apex " + dns.Type(qtype).String(), qname: zone, qtype: qtype, rcodes: noError, authoritative: true, check: noData})
	}
	cases = append(cases,
		dnsCase{name: "ANY at an address name", qname: "10-11-12-13." + zone, qtype: dns.TypeANY, rcodes: noError, authoritative: true, check: expectHINFO},
		dnsCase{name: "ANY at the apex", qname: zone, qtype: dns.TypeANY, rcodes: noError, authoritative: true, check: expectHINFO},
	)
	cases = append(cases, declaredRecordCases(tg)...)
	cases = append(cases,
		dnsCase{name: "mixed case dashed with prefix", qname: alternateCase("app.10-11-12-13." + zone), qtype: dns.TypeA, rcodes: noError, authoritative: true, check: expectA(want)},
	)
	unrelated, sibling := outsideNames(zone)
	cases = append(cases,
		dnsCase{name: "outside zone", qname: unrelated, qtype: dns.TypeA, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "outside zone sibling with the same suffix", qname: sibling, qtype: dns.TypeA, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "class CH", qname: zone, qtype: dns.TypeTXT, qclass: dns.ClassCHAOS, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "zone transfer AXFR", qname: zone, qtype: dns.TypeAXFR, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
		dnsCase{name: "zone transfer IXFR", qname: zone, qtype: dns.TypeIXFR, rcodes: refused, nonAuthoritative: true, check: expectNoRecords},
	)
	return append(cases, transportCases(tg)...)
}

// The zone file may declare a TXT set at each of these labels below the apex for the suite to verify truncation, EDNS and TCP with: every reply for the first is larger than 512 octets and smaller than serverUDPSize, every reply for the second is larger than serverUDPSize. checkTransportSets holds a declared set to that.
const (
	udpTXTLabel = "e2e-txt-udp"
	tcpTXTLabel = "e2e-txt-tcp"
)

// txtSetAt returns the TXT set the zone file declares at the label below the apex, if any.
func (tg *target) txtSetAt(label string) (targetRecordSet, bool) {
	return tg.recordSet(label+"."+tg.zone(), dns.TypeTXT)
}

// transportCases are the cases of every name server that depend on the transport and on EDNS; the cases for the large TXT sets exist only where the zone file declares them.
func transportCases(tg *target) []dnsCase {
	zone := tg.zone()
	noError := []int{dns.RcodeSuccess}
	edns := ednsOPT{udpSize: serverUDPSize}
	unrelated, _ := outsideNames(zone)
	cases := []dnsCase{
		{name: "address over TCP", qname: "10-11-12-13." + zone, qtype: dns.TypeA, tcp: true, rcodes: noError, authoritative: true, check: expectA(netip.MustParseAddr("10.11.12.13"))},
		{name: "EDNS version 1 gets BADVERS", qname: zone, qtype: dns.TypeSOA, edns: ednsOPT{udpSize: serverUDPSize, version: 1}, rcodes: []int{dns.RcodeBadVers}, nonAuthoritative: true, check: expectNoRecords},
		{name: "EDNS on NXDOMAIN", qname: nameOfWireLength(zone, 254), qtype: dns.TypeA, edns: edns, rcodes: []int{dns.RcodeNameError}, authoritative: true, check: expectNameError(tg.soa)},
		{name: "EDNS on REFUSED", qname: unrelated, qtype: dns.TypeA, edns: edns, rcodes: []int{dns.RcodeRefused}, nonAuthoritative: true, check: expectNoRecords},
	}
	if set, ok := tg.txtSetAt(udpTXTLabel); ok {
		cases = append(cases,
			dnsCase{name: set.owner + " TXT over UDP without EDNS is truncated", qname: set.owner, qtype: dns.TypeTXT, truncated: true, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectPartOfRecordSet(set)},
			dnsCase{name: set.owner + " TXT with EDNS 1232 is whole", qname: set.owner, qtype: dns.TypeTXT, edns: edns, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)},
		)
	}
	if set, ok := tg.txtSetAt(tcpTXTLabel); ok {
		cases = append(cases,
			dnsCase{name: set.owner + " TXT with EDNS 4096 is truncated at 1232", qname: set.owner, qtype: dns.TypeTXT, edns: ednsOPT{udpSize: 4096}, truncated: true, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectPartOfRecordSet(set)},
			dnsCase{name: set.owner + " TXT over TCP is whole", qname: set.owner, qtype: dns.TypeTXT, tcp: true, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)},
			dnsCase{name: set.owner + " TXT over TCP with EDNS 512 is whole", qname: set.owner, qtype: dns.TypeTXT, tcp: true, edns: ednsOPT{udpSize: 512}, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set)},
		)
	}
	return cases
}

// checkTransportSets holds the TXT sets the zone file declares at the transport labels to the sizes their cases rely on. The smallest reply is the compressed one without an OPT record, the largest the uncompressed one with the OPT record of the reply: a server compresses only when a reply would not fit otherwise.
func checkTransportSets(tg *target) error {
	if set, ok := tg.txtSetAt(udpTXTLabel); ok {
		smallest, err := replySize(set, true, false)
		if err != nil {
			return err
		}
		if smallest <= dns.MinMsgSize {
			return fmt.Errorf("the TXT set at %s has a reply of %d octets without EDNS, want more than %d so that it is truncated", set.owner, smallest, dns.MinMsgSize)
		}
		largest, err := replySize(set, false, true)
		if err != nil {
			return err
		}
		if largest >= serverUDPSize {
			return fmt.Errorf("the TXT set at %s has a reply of %d octets with EDNS, want less than %d so that it is whole", set.owner, largest, serverUDPSize)
		}
	}
	if set, ok := tg.txtSetAt(tcpTXTLabel); ok {
		smallest, err := replySize(set, true, true)
		if err != nil {
			return err
		}
		if smallest <= serverUDPSize {
			return fmt.Errorf("the TXT set at %s has a reply of %d octets with EDNS, want more than %d so that it is truncated over UDP", set.owner, smallest, serverUDPSize)
		}
	}
	return nil
}

// replySize packs the reply that carries the whole set, compressed or not, with or without the OPT record a name server adds, and returns its length in octets.
func replySize(set targetRecordSet, compress, withOPT bool) (int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(set.owner, set.rrtype)
	msg.Response = true
	msg.Answer = set.records
	if withOPT {
		msg.SetEdns0(serverUDPSize, false)
	}
	msg.Compress = compress
	packed, err := msg.Pack()
	if err != nil {
		return 0, fmt.Errorf("packing a reply with the %s set at %s: %w", dns.Type(set.rrtype), set.owner, err)
	}
	return len(packed), nil
}

// declaredRecordCases asks for every record set the target's zone file declares, as written and in mixed case, and asks each name for a type it has none of. A CNAME is also asked for types it is not, which it answers in their place. A set may be too large for a reply without EDNS, so the cases that expect one follow truncation.
func declaredRecordCases(tg *target) []dnsCase {
	noError := []int{dns.RcodeSuccess}
	var cases []dnsCase
	var ownersWithoutCNAME []string
	for _, set := range tg.recordSets {
		label := set.owner + " " + dns.Type(set.rrtype).String()
		cases = append(cases,
			dnsCase{name: "declared " + label, qname: set.owner, qtype: set.rrtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set), checkTruncated: expectPartOfRecordSet(set)},
			dnsCase{name: "mixed case declared " + label, qname: alternateCase(set.owner), qtype: set.rrtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set), checkTruncated: expectPartOfRecordSet(set)},
		)
		if set.rrtype == dns.TypeCNAME {
			for _, qtype := range []uint16{dns.TypeA, dns.TypeNS} {
				cases = append(cases, dnsCase{name: "declared " + label + " asked for " + dns.Type(qtype).String(), qname: set.owner, qtype: qtype, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectRecordSet(set), checkTruncated: expectPartOfRecordSet(set)})
			}
		} else if !slices.Contains(ownersWithoutCNAME, set.owner) {
			ownersWithoutCNAME = append(ownersWithoutCNAME, set.owner)
		}
	}
	// HTTPS is a type the zone file cannot declare, so every declared name lacks it.
	for _, owner := range ownersWithoutCNAME {
		cases = append(cases, dnsCase{name: "declared name " + owner + " asked for HTTPS", qname: owner, qtype: dns.TypeHTTPS, rcodes: noError, authoritative: true, fromZoneFile: true, check: expectNoData(tg.soa)})
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
	cases := []dnsCase{
		{name: "dashed with random prefix", qname: label() + ".10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(want)},
		{name: "dashed with random prefix in the label", qname: label() + "-10-11-12-13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(want)},
		// The resolver minimises the query name on its way and passes through 13.<zone>, 12.13.<zone> and 11.12.13.<zone>, where an NXDOMAIN would tell it that nothing exists below (RFC 8020).
		{name: "dotted with random prefix", qname: label() + ".10.11.12.13." + zone, qtype: dns.TypeA, rcodes: noError, check: expectA(want)},
		{name: "apex NS", qname: zone, qtype: dns.TypeNS, rcodes: noError, check: expectNS(tg.apexNSTargets())},
	}
	// The resolver is asked over TCP so that its own limits on UDP cannot cut the set; whole sets show that it got them whole from a name server, over UDP with EDNS or over TCP after a truncated reply.
	for _, txtLabel := range []string{udpTXTLabel, tcpTXTLabel} {
		if set, ok := tg.txtSetAt(txtLabel); ok {
			cases = append(cases, dnsCase{name: set.owner + " TXT over TCP is whole", qname: set.owner, qtype: dns.TypeTXT, tcp: true, rcodes: noError, fromZoneFile: true, check: expectCachedRecordSet(set)})
		}
	}
	return cases
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
	if err := checkProbeCases(tg, authoritativeCases(tg)); err != nil {
		return err
	}
	for _, host := range lanRoundTripHosts(tg.domain) {
		if err := checkProbeName(tg, host, "the certificate round trip through "+host); err != nil {
			return err
		}
	}
	return nil
}

// checkProbeCases holds the name of every case to checkProbeName; a case generated from the zone file is left out, because it asks for a declared name by construction.
func checkProbeCases(tg *target, cases []dnsCase) error {
	for _, tc := range cases {
		if tc.fromZoneFile {
			continue
		}
		if err := checkProbeName(tg, tc.qname, fmt.Sprintf("the case %q", tc.name)); err != nil {
			return err
		}
	}
	return nil
}

// checkProbeName refuses a name below the apex that the zone file declares a record at or delegates, the names the suite reserves for its probes; askedBy names the probe in the error.
func checkProbeName(tg *target, qname, askedBy string) error {
	zone := tg.zone()
	name := dns.CanonicalName(qname)
	if name == zone || !dns.IsSubDomain(zone, name) {
		return nil
	}
	for _, set := range tg.recordSets {
		if set.owner == name {
			return fmt.Errorf("the name %s, which %s asks for, is reserved for the suite's probes, and the zone file declares %s %s there", name, askedBy, set.owner, dns.Type(set.rrtype))
		}
	}
	for _, d := range tg.delegations {
		if dns.IsSubDomain(d.cut, name) {
			return fmt.Errorf("the name %s, which %s asks for, is reserved for the suite's probes, and the zone file delegates it or a name above it: %s NS", name, askedBy, d.cut)
		}
	}
	return nil
}

func delegationChecks(t *testing.T, tg *target) {
	if len(tg.delegations) == 0 {
		t.Skipf("%s declares no delegations in its zone file", tg.name)
	}
	noError := []int{dns.RcodeSuccess}

	for _, server := range tg.dnsServers {
		t.Run(server.String(), func(t *testing.T) {
			for i, d := range tg.delegations {
				silent := false
				t.Run(d.cut, func(t *testing.T) {
					referral := expectReferral(d)
					partOfReferral := asCheck(func(resp *dns.Msg) error { return checkPartOfReferral(d, resp) })
					cases := []dnsCase{
						{name: "cut NS", qname: d.cut, qtype: dns.TypeNS, rcodes: noError, nonAuthoritative: true, check: referral, checkTruncated: partOfReferral},
						{name: "random name A", qname: randomLabel(t) + "." + d.cut, qtype: dns.TypeA, rcodes: noError, nonAuthoritative: true, check: referral, checkTruncated: partOfReferral},
						{name: "dashed A", qname: "10-11-12-13." + d.cut, qtype: dns.TypeA, rcodes: noError, nonAuthoritative: true, check: referral, checkTruncated: partOfReferral},
						{name: "ACME challenge TXT", qname: "_acme-challenge." + d.cut, qtype: dns.TypeTXT, rcodes: noError, nonAuthoritative: true, check: referral, checkTruncated: partOfReferral},
						// DS records belong to the parent, so this server answers for them from its own zone.
						{name: "cut DS", qname: d.cut, qtype: dns.TypeDS, rcodes: noError, authoritative: true, check: expectNoData(tg.soa)},
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

// checkPartOfReferral checks a truncated referral to the delegation: no answer, and only records the whole referral carries, each at most once: NS records of the cut with its declared targets in the authority section and its declared glue in the additional section. At least one of them must be missing, since a server truncates only when the whole referral does not fit.
func checkPartOfReferral(d targetDelegation, resp *dns.Msg) error {
	if len(resp.Answer) != 0 {
		return fmt.Errorf("answer section has %d records, want none in a referral to %s", len(resp.Answer), d.cut)
	}
	records, err := recordsOfType[*dns.NS](resp.Ns, d.cut, dns.TypeNS)
	if err != nil {
		return fmt.Errorf("authority section, want only NS records of %s: %w", d.cut, err)
	}
	remainingNS := slices.Clone(d.nameServers)
	for _, record := range records {
		i := slices.Index(remainingNS, strings.ToLower(record.Ns))
		if i < 0 {
			return fmt.Errorf("authority NS target %s is not one of the declared %v, or appears twice", record.Ns, d.nameServers)
		}
		remainingNS = slices.Delete(remainingNS, i, i+1)
	}
	type glueRecord struct {
		nameServer string
		addr       netip.Addr
	}
	var remainingGlue []glueRecord
	for nameServer, addrs := range d.glue {
		for _, addr := range addrs {
			remainingGlue = append(remainingGlue, glueRecord{nameServer, addr})
		}
	}
	for _, rr := range resp.Extra {
		i := slices.IndexFunc(remainingGlue, func(g glueRecord) bool { return hasGlue([]dns.RR{rr}, g.nameServer, g.addr) })
		if i < 0 {
			return fmt.Errorf("additional record %q is not declared glue of %s, or appears twice", rr, d.cut)
		}
		remainingGlue = slices.Delete(remainingGlue, i, i+1)
	}
	if len(remainingNS) == 0 && len(remainingGlue) == 0 {
		return fmt.Errorf("truncated referral to %s carries every NS and glue record, want some of them missing", d.cut)
	}
	return nil
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

// testTarget is the target of the example zone, example.test, with the SOA record testSOA and three name servers: ns1 with two A records and an AAAA record, ns2 with one A record, and one outside the zone.
func testTarget(t *testing.T) *target {
	t.Helper()
	soa, err := comparableRecord(mustRR(t, testSOA))
	if err != nil {
		t.Fatal(err)
	}
	var additional []dns.RR
	for _, record := range []string{"ns1.example.test. 3600 IN A 192.0.2.10", "ns1.example.test. 3600 IN A 192.0.2.12", "ns1.example.test. 3600 IN AAAA 2001:db8::10", "ns2.example.test. 3600 IN A 192.0.2.11"} {
		rr, err := comparableRecord(mustRR(t, record))
		if err != nil {
			t.Fatal(err)
		}
		additional = append(additional, rr)
	}
	return &target{
		domain:           "example.test",
		dnsServers:       []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.12"), netip.MustParseAddr("192.0.2.11")},
		webAddresses:     []netip.Addr{netip.MustParseAddr("192.0.2.80")},
		soa:              soa.(*dns.SOA),
		apexNS:           testRecordSet(t, "example.test. 3600 IN NS ns1.example.test.", "example.test. 3600 IN NS ns2.example.test.", "example.test. 3600 IN NS ns.other.test."),
		apexNSAdditional: additional,
	}
}

func TestCheckApexSOA(t *testing.T) {
	soaField := func(set func(*dns.SOA)) func(*dns.Msg) {
		return func(resp *dns.Msg) { set(resp.Answer[0].(*dns.SOA)) }
	}
	tests := []struct {
		name   string
		qname  string
		rcode  int
		answer []string
		mutate func(resp *dns.Msg)
		ok     bool
	}{
		{name: "accepts the zone file's SOA record", answer: []string{testSOA}, ok: true},
		{name: "accepts a question in mixed case answered by its owner as asked", qname: "ExAmPlE.test.", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.Answer[0].Header().Name = "ExAmPlE.test." }, ok: true},
		{name: "accepts the MNAME in another case", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Ns = "NS1.Example.Test." }), ok: true},
		{name: "accepts the RNAME in another case", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Mbox = "Admin.Example.Test." }), ok: true},
		{name: "rejects another rcode", rcode: dns.RcodeServerFailure, answer: []string{testSOA}},
		{name: "rejects an empty answer", answer: nil},
		{name: "rejects two SOA records", answer: []string{testSOA, testSOA}},
		{name: "rejects a record of another type in the answer", answer: []string{testSOA, "example.test. 300 IN NS ns1.example.test."}},
		{name: "rejects an SOA record in class CH", answer: []string{"example.test. 300 CH SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"}},
		{name: "rejects an SOA record owned by another name", answer: []string{testSOA}, mutate: func(resp *dns.Msg) { resp.Answer[0].Header().Name = "www.example.test." }},
		{name: "rejects another MNAME", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Ns = "ns2.example.test." })},
		{name: "rejects another RNAME", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Mbox = "hostmaster.example.test." })},
		{name: "rejects another serial", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Serial++ })},
		{name: "rejects another refresh", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Refresh++ })},
		{name: "rejects another retry", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Retry++ })},
		{name: "rejects another expire", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Expire++ })},
		{name: "rejects another minimum", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Minttl++ })},
		{name: "rejects a larger TTL", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Hdr.Ttl++ })},
		{name: "rejects a smaller TTL", answer: []string{testSOA}, mutate: soaField(func(soa *dns.SOA) { soa.Hdr.Ttl-- })},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qname := cmp.Or(tt.qname, "example.test.")
			resp := testReply(t, qname, dns.TypeSOA, tt.rcode, tt.answer, nil, nil)
			if tt.mutate != nil {
				tt.mutate(resp)
			}
			assertCheck(t, checkApexSOA(testTarget(t), resp), tt.ok)
		})
	}
}

func TestCheckApexNS(t *testing.T) {
	const (
		ns1     = "ExAmPlE.test. 3600 IN NS ns1.example.test."
		ns2     = "ExAmPlE.test. 3600 IN NS ns2.example.test."
		nsOther = "ExAmPlE.test. 3600 IN NS ns.other.test."
		ns1A    = "ns1.example.test. 3600 IN A 192.0.2.10"
		ns1A2   = "ns1.example.test. 3600 IN A 192.0.2.12"
		ns1AAAA = "ns1.example.test. 3600 IN AAAA 2001:db8::10"
		ns2A    = "ns2.example.test. 3600 IN A 192.0.2.11"
	)
	tests := []struct {
		name string
		// answer and additional are those of the whole answer when nil.
		answer     []string
		authority  []string
		additional []string
		ok         bool
	}{
		{name: "accepts the NS records and the addresses of the name servers inside the zone", ok: true},
		{name: "accepts the NS records in another order", answer: []string{nsOther, ns2, ns1}, ok: true},
		{name: "accepts NS targets and owners of addresses in another case", answer: []string{"ExAmPlE.test. 3600 IN NS NS1.Example.TEST.", ns2, nsOther}, additional: []string{"NS1.Example.TEST. 3600 IN A 192.0.2.10", ns1A2, ns1AAAA, ns2A}, ok: true},
		{name: "rejects a missing NS record", answer: []string{ns1, ns2}},
		{name: "rejects an NS record that is not declared", answer: []string{ns1, ns2, nsOther, "ExAmPlE.test. 3600 IN NS ns3.example.test."}},
		{name: "rejects an NS record with another TTL", answer: []string{ns1, ns2, "ExAmPlE.test. 300 IN NS ns.other.test."}},
		{name: "rejects a record in the authority section", authority: []string{testSOA}},
		{name: "rejects an empty additional section", additional: []string{}},
		{name: "rejects a missing address record", additional: []string{ns1A, ns1A2, ns2A}},
		{name: "rejects an extra address record of a name server", additional: []string{ns1A, ns1A2, ns1AAAA, ns2A, "ns2.example.test. 3600 IN AAAA 2001:db8::11"}},
		{name: "rejects an address record of the name server outside the zone", additional: []string{ns1A, ns1A2, ns1AAAA, ns2A, "ns.other.test. 3600 IN A 192.0.2.99"}},
		{name: "rejects a name server's A records in another order", additional: []string{ns1A2, ns1A, ns1AAAA, ns2A}},
		{name: "rejects a name server's AAAA record in front of its A records", additional: []string{ns1AAAA, ns1A, ns1A2, ns2A}},
		{name: "rejects the name servers' addresses in another order than their NS records", additional: []string{ns2A, ns1A, ns1A2, ns1AAAA}},
		{name: "rejects an address record with another TTL", additional: []string{ns1A, ns1A2, "ns1.example.test. 300 IN AAAA 2001:db8::10", ns2A}},
		{name: "rejects another address", additional: []string{ns1A, "ns1.example.test. 3600 IN A 192.0.2.13", ns1AAAA, ns2A}},
		{name: "rejects an address in class CH", additional: []string{ns1A, ns1A2, ns1AAAA, "ns2.example.test. 3600 CH A 192.0.2.11"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer, additional := tt.answer, tt.additional
			if answer == nil {
				answer = []string{ns1, ns2, nsOther}
			}
			if additional == nil {
				additional = []string{ns1A, ns1A2, ns1AAAA, ns2A}
			}
			resp := testReply(t, "ExAmPlE.test.", dns.TypeNS, dns.RcodeSuccess, answer, tt.authority, additional)
			assertCheck(t, checkApexNS(testTarget(t), resp), tt.ok)
		})
	}
}

func TestCheckProbeCases(t *testing.T) {
	tg := testTarget(t)
	tg.delegations = []targetDelegation{
		{cut: "e2e-12345678.10-11-12-13.example.test.", nameServers: []string{"ns.other.test."}},
		{cut: "e2e-abcdef01-10-11-12-13.example.test.", nameServers: []string{"ns.other.test."}},
	}
	tg.recordSets = []targetRecordSet{{owner: "e2e-87654321.10.11.12.13.example.test.", rrtype: dns.TypeTXT, ttl: 300}}
	tests := []struct {
		name    string
		label   string
		wantErr []string
	}{
		{name: "accepts generated names the zone file does not touch", label: "e2e-00000000"},
		{name: "rejects a generated name the zone file delegates", label: "e2e-12345678", wantErr: []string{"e2e-12345678.10-11-12-13.example.test.", `"dashed with random prefix"`, "reserved for the suite's probes", "delegates it or a name above it: e2e-12345678.10-11-12-13.example.test. NS"}},
		{name: "rejects a generated name in the label the zone file delegates", label: "e2e-abcdef01", wantErr: []string{"e2e-abcdef01-10-11-12-13.example.test.", `"dashed with random prefix in the label"`, "reserved for the suite's probes", "delegates it or a name above it: e2e-abcdef01-10-11-12-13.example.test. NS"}},
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

func TestCheckCachedRecordSet(t *testing.T) {
	set := testRecordSet(t, `example.test. 300 IN TXT "one"`, `example.test. 300 IN TXT "two"`)
	tests := []struct {
		name   string
		answer []string
		ok     bool
	}{
		{name: "accepts the declared TTL", answer: []string{`example.test. 300 IN TXT "one"`, `example.test. 300 IN TXT "two"`}, ok: true},
		{name: "accepts a TTL counted down in a cache", answer: []string{`example.test. 17 IN TXT "two"`, `example.test. 17 IN TXT "one"`}, ok: true},
		{name: "rejects a TTL above the declared one", answer: []string{`example.test. 301 IN TXT "one"`, `example.test. 301 IN TXT "two"`}},
		{name: "rejects a missing record", answer: []string{`example.test. 300 IN TXT "one"`}},
		{name: "rejects another record", answer: []string{`example.test. 300 IN TXT "one"`, `example.test. 300 IN TXT "three"`}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "example.test.", dns.TypeTXT, dns.RcodeSuccess, tt.answer, nil, nil)
			assertCheck(t, checkCachedRecordSet(set, resp), tt.ok)
		})
	}
}

func TestCheckPartOfRecordSet(t *testing.T) {
	set := testRecordSet(t, `example.test. 300 IN TXT "one"`, `example.test. 300 IN TXT "two"`, `example.test. 300 IN TXT "three"`)
	const one = `ExAmPlE.test. 300 IN TXT "one"`
	const two = `ExAmPlE.test. 300 IN TXT "two"`
	tests := []struct {
		name       string
		answer     []string
		additional []string
		ok         bool
	}{
		{name: "accepts some of the declared records", answer: []string{one, two}, ok: true},
		{name: "accepts no record at all", ok: true},
		{name: "rejects every declared record", answer: []string{one, two, `ExAmPlE.test. 300 IN TXT "three"`}},
		{name: "rejects a record that is not declared", answer: []string{one, `ExAmPlE.test. 300 IN TXT "four"`}},
		{name: "rejects a declared record twice", answer: []string{one, one}},
		{name: "rejects a record with another TTL", answer: []string{one, `ExAmPlE.test. 299 IN TXT "two"`}},
		{name: "rejects a record owned by another name", answer: []string{one, `www.example.test. 300 IN TXT "two"`}},
		{name: "rejects a record in the additional section", answer: []string{one}, additional: []string{"ns1.example.test. 300 IN A 192.0.2.10"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "ExAmPlE.test.", dns.TypeTXT, dns.RcodeSuccess, tt.answer, nil, tt.additional)
			assertCheck(t, checkPartOfRecordSet(set, resp), tt.ok)
		})
	}
}

func TestCheckTruncation(t *testing.T) {
	tests := []struct {
		name      string
		expected  bool
		follow    bool
		truncated bool
		ok        bool
	}{
		{name: "accepts a whole reply where none is expected truncated", ok: true},
		{name: "accepts a truncated reply where the query follows truncation", follow: true, truncated: true, ok: true},
		{name: "accepts a whole reply where the query follows truncation", follow: true, ok: true},
		{name: "accepts a truncated reply where one is expected", expected: true, truncated: true, ok: true},
		{name: "rejects a truncated reply where a whole one is expected", truncated: true},
		{name: "rejects a whole reply where a truncated one is expected", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "example.test.", dns.TypeTXT, dns.RcodeSuccess, nil, nil, nil)
			resp.Truncated = tt.truncated
			assertCheck(t, checkTruncation(dnsQuery{name: "example.test.", qtype: dns.TypeTXT, qclass: dns.ClassINET, truncated: tt.expected, followTruncation: tt.follow}, resp), tt.ok)
		})
	}
}

func TestCheckReplyOPT(t *testing.T) {
	withEDNS := dnsQuery{name: "example.test.", qtype: dns.TypeSOA, qclass: dns.ClassINET, edns: ednsOPT{udpSize: 4096}}
	withoutEDNS := dnsQuery{name: "example.test.", qtype: dns.TypeSOA, qclass: dns.ClassINET}
	tests := []struct {
		name   string
		query  dnsQuery
		rcode  int
		mutate func(resp *dns.Msg)
		ok     bool
	}{
		{name: "accepts the OPT record of the server", query: withEDNS, ok: true},
		{name: "accepts the OPT record of the server on BADVERS", query: withEDNS, rcode: dns.RcodeBadVers, ok: true},
		{name: "accepts no OPT record in reply to a query without one", query: withoutEDNS, mutate: func(resp *dns.Msg) { resp.Extra = nil }, ok: true},
		{name: "rejects an OPT record in reply to a query without one", query: withoutEDNS},
		{name: "rejects no OPT record in reply to a query with one", query: withEDNS, mutate: func(resp *dns.Msg) { resp.Extra = nil }},
		{name: "rejects two OPT records", query: withEDNS, mutate: func(resp *dns.Msg) { resp.SetEdns0(serverUDPSize, false) }},
		{name: "rejects the size of the query echoed", query: withEDNS, mutate: func(resp *dns.Msg) { resp.IsEdns0().SetUDPSize(4096) }},
		{name: "rejects a size of 512", query: withEDNS, mutate: func(resp *dns.Msg) { resp.IsEdns0().SetUDPSize(512) }},
		{name: "rejects version 1", query: withEDNS, mutate: func(resp *dns.Msg) { resp.IsEdns0().SetVersion(1) }},
		{name: "rejects the DO flag set", query: withEDNS, mutate: func(resp *dns.Msg) { resp.IsEdns0().SetDo() }},
		{name: "rejects an option", query: withEDNS, mutate: func(resp *dns.Msg) {
			opt := resp.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e73"})
		}},
		{name: "rejects an owner other than the root", query: withEDNS, mutate: func(resp *dns.Msg) { resp.IsEdns0().Hdr.Name = "example.test." }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "example.test.", dns.TypeSOA, tt.rcode, nil, nil, nil)
			resp.SetEdns0(serverUDPSize, false)
			if tt.mutate != nil {
				tt.mutate(resp)
			}
			packed, err := resp.Pack()
			if err != nil {
				t.Fatal(err)
			}
			wire := new(dns.Msg)
			if err := wire.Unpack(packed); err != nil {
				t.Fatal(err)
			}
			if wire.Rcode != tt.rcode {
				t.Fatalf("rcode after a wire round trip = %d, want %d", wire.Rcode, tt.rcode)
			}
			assertCheck(t, checkReplyOPT(tt.query, wire), tt.ok)
		})
	}
}

// startFakeDNS serves reply over UDP and TCP on one port of the loopback address and records the transport of every question it gets, in order. A nil reply closes the connection without replying.
func startFakeDNS(t *testing.T, reply func(tcp bool, req *dns.Msg) *dns.Msg) (netip.AddrPort, func() []string) {
	t.Helper()
	var asked []string
	var mu sync.Mutex
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		tcp := w.LocalAddr().Network() == "tcp"
		mu.Lock()
		asked = append(asked, w.LocalAddr().Network())
		mu.Unlock()
		resp := reply(tcp, req)
		if resp == nil {
			_ = w.Close()
			return
		}
		resp.Id = req.Id
		_ = w.WriteMsg(resp)
	})

	var conn net.PacketConn
	var listener net.Listener
	for range 20 {
		var err error
		conn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener, err = net.Listen("tcp", conn.LocalAddr().String())
		if err == nil {
			break
		}
		conn.Close()
		conn = nil
	}
	if conn == nil {
		t.Fatal("found no port free over both UDP and TCP")
	}
	for _, server := range []*dns.Server{{PacketConn: conn, Handler: handler}, {Listener: listener, Handler: handler}} {
		started := make(chan struct{})
		server.NotifyStartedFunc = func() { close(started) }
		go func() { _ = server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	return netip.MustParseAddrPort(conn.LocalAddr().String()), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

func TestAskCaseFollowsTruncation(t *testing.T) {
	const qname = "big.example.test."
	set := testRecordSet(t, `big.example.test. 300 IN TXT "one"`, `big.example.test. 300 IN TXT "two"`, `big.example.test. 300 IN TXT "three"`)
	replyWith := func(req *dns.Msg, truncated bool, records ...dns.RR) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.Truncated = truncated
		resp.Answer = records
		return resp
	}
	tc := dnsCase{name: "declared", qname: qname, qtype: dns.TypeTXT, rcodes: []int{dns.RcodeSuccess}, authoritative: true, check: expectRecordSet(set), checkTruncated: expectPartOfRecordSet(set)}
	tests := []struct {
		name          string
		reply         func(tcp bool, req *dns.Msg) *dns.Msg
		wantAsked     []string
		wantTruncated bool
		wantErr       bool
		finalOK       bool
	}{
		{
			name:      "accepts a reply that fits without asking over TCP",
			reply:     func(_ bool, req *dns.Msg) *dns.Msg { return replyWith(req, false, set.records...) },
			wantAsked: []string{"udp"},
			finalOK:   true,
		},
		{
			name: "accepts a truncated reply followed by the whole set over TCP",
			reply: func(tcp bool, req *dns.Msg) *dns.Msg {
				if tcp {
					return replyWith(req, false, set.records...)
				}
				return replyWith(req, true, set.records[0])
			},
			wantAsked:     []string{"udp", "tcp"},
			wantTruncated: true,
			finalOK:       true,
		},
		{
			name: "rejects a reply over TCP that still lacks a record",
			reply: func(tcp bool, req *dns.Msg) *dns.Msg {
				if tcp {
					return replyWith(req, false, set.records[:2]...)
				}
				return replyWith(req, true, set.records[0])
			},
			wantAsked:     []string{"udp", "tcp"},
			wantTruncated: true,
		},
		{
			name:          "rejects a reply over TCP that is truncated again",
			reply:         func(_ bool, req *dns.Msg) *dns.Msg { return replyWith(req, true, set.records[0]) },
			wantAsked:     []string{"udp", "tcp"},
			wantTruncated: true,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, asked := startFakeDNS(t, tt.reply)
			resp, truncated, q, err := askCase(t, server, toNameServer, tc)
			if got := asked(); !slices.Equal(got, tt.wantAsked) {
				t.Errorf("questions over %v, want %v", got, tt.wantAsked)
			}
			if (truncated != nil) != tt.wantTruncated {
				t.Fatalf("truncated reply = %v, want one: %t", truncated, tt.wantTruncated)
			}
			if truncated != nil {
				assertCheck(t, checkPartOfRecordSet(set, withoutOPT(truncated)), true)
			}
			if q.tcp != (len(tt.wantAsked) == 2) {
				t.Errorf("final query over TCP = %t, want %t", q.tcp, len(tt.wantAsked) == 2)
			}
			if tt.wantErr {
				if err == nil {
					t.Error("askCase accepted the reply over TCP, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertCheck(t, checkRecordSet(set, withoutOPT(resp)), tt.finalOK)
		})
	}
}

// shortenDNSRetryPauses keeps the number of attempts and makes the pauses between them negligible for the test.
func shortenDNSRetryPauses(t *testing.T) {
	saved := dnsRetryPauses
	dnsRetryPauses = make([]time.Duration, len(saved))
	for i := range dnsRetryPauses {
		dnsRetryPauses[i] = time.Millisecond
	}
	t.Cleanup(func() { dnsRetryPauses = saved })
}

func TestExchangeRetriesATCPConnectionClosedWithoutAReply(t *testing.T) {
	shortenDNSRetryPauses(t)
	var mu sync.Mutex
	connections := 0
	server, asked := startFakeDNS(t, func(_ bool, req *dns.Msg) *dns.Msg {
		mu.Lock()
		defer mu.Unlock()
		connections++
		if connections == 1 {
			return nil
		}
		resp := testReply(t, "10-11-12-13.example.test.", dns.TypeA, dns.RcodeSuccess, []string{"10-11-12-13.example.test. 300 IN A 10.11.12.13"}, nil, nil)
		resp.RecursionDesired = req.RecursionDesired
		return resp
	})
	tc := dnsCase{qname: "10-11-12-13.example.test.", qtype: dns.TypeA, tcp: true}
	resp, err := exchangeAt(t, server, tc.query(toNameServer))
	if err != nil {
		t.Fatalf("exchangeAt failed: %v", err)
	}
	expectA(netip.MustParseAddr("10.11.12.13"))(t, resp)
	if got, want := asked(), []string{"tcp", "tcp"}; !slices.Equal(got, want) {
		t.Errorf("questions over %v, want %v", got, want)
	}
}

func TestExchangeGivesUpWhenEveryTCPConnectionIsClosedWithoutAReply(t *testing.T) {
	shortenDNSRetryPauses(t)
	server, asked := startFakeDNS(t, func(bool, *dns.Msg) *dns.Msg { return nil })
	tc := dnsCase{qname: "10-11-12-13.example.test.", qtype: dns.TypeA, tcp: true}
	_, err := exchangeAt(t, server, tc.query(toNameServer))
	if !errors.Is(err, errNoDNSResponse) {
		t.Fatalf("exchangeAt error = %v, want %v", err, errNoDNSResponse)
	}
	if got, want := len(asked()), len(dnsRetryPauses)+1; got != want {
		t.Errorf("%d TCP connections, want one per attempt, %d", got, want)
	}
}

func TestCheckPartOfReferral(t *testing.T) {
	d := targetDelegation{
		cut:         "sub.example.test.",
		nameServers: []string{"ns.other.test.", "ns1.sub.example.test."},
		glue:        map[string][]netip.Addr{"ns1.sub.example.test.": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}},
	}
	const ns1 = "sub.example.test. 300 IN NS ns1.sub.example.test."
	const nsOther = "SUB.example.test. 300 IN NS NS.OTHER.TEST."
	const glueA = "ns1.sub.example.test. 300 IN A 192.0.2.1"
	const glueAAAA = "ns1.sub.example.test. 300 IN AAAA 2001:db8::1"
	tests := []struct {
		name       string
		answer     []string
		authority  []string
		additional []string
		ok         bool
	}{
		{name: "accepts the NS records without glue", authority: []string{ns1, nsOther}, ok: true},
		{name: "accepts the NS records with part of the glue", authority: []string{ns1, nsOther}, additional: []string{glueA}, ok: true},
		{name: "accepts part of the NS records", authority: []string{ns1}, ok: true},
		{name: "rejects the whole referral", authority: []string{ns1, nsOther}, additional: []string{glueA, glueAAAA}},
		{name: "rejects an answer record", answer: []string{"www.sub.example.test. 300 IN A 192.0.2.80"}, authority: []string{ns1}},
		{name: "rejects an NS target that is not declared", authority: []string{ns1, "sub.example.test. 300 IN NS ns.elsewhere.test."}},
		{name: "rejects an NS record twice", authority: []string{ns1, ns1}},
		{name: "rejects an NS record of another name", authority: []string{"example.test. 300 IN NS ns1.sub.example.test."}},
		{name: "rejects glue that is not declared", authority: []string{ns1}, additional: []string{"ns1.sub.example.test. 300 IN A 192.0.2.2"}},
		{name: "rejects glue twice", authority: []string{ns1}, additional: []string{glueA, glueA}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, "www.sub.example.test.", dns.TypeA, dns.RcodeSuccess, tt.answer, tt.authority, tt.additional)
			resp.Authoritative = false
			assertCheck(t, checkPartOfReferral(d, resp), tt.ok)
		})
	}
}

func TestWithoutOPT(t *testing.T) {
	resp := testReply(t, "example.test.", dns.TypeSOA, dns.RcodeSuccess, nil, nil, []string{"ns1.example.test. 300 IN A 192.0.2.10"})
	resp.SetEdns0(serverUDPSize, false)
	content := withoutOPT(resp)
	if len(content.Extra) != 1 || content.Extra[0].Header().Rrtype != dns.TypeA {
		t.Errorf("additional section without OPT = %v, want the A record alone", content.Extra)
	}
	if resp.IsEdns0() == nil {
		t.Error("withoutOPT removed the OPT record from the reply it was given")
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

func TestCheckTTL(t *testing.T) {
	const qname = "10-11-12-13.example.test."
	tests := []struct {
		name   string
		answer []string
		ok     bool
	}{
		{name: "accepts the TTL", answer: []string{qname + " 86400 IN A 10.11.12.13"}, ok: true},
		{name: "rejects a smaller TTL", answer: []string{qname + " 86399 IN A 10.11.12.13"}},
		{name: "rejects a larger TTL", answer: []string{qname + " 86401 IN A 10.11.12.13"}},
		{name: "rejects one record of two with another TTL", answer: []string{qname + " 86400 IN A 10.11.12.13", qname + " 300 IN A 10.11.12.14"}},
		{name: "rejects an empty answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := testReply(t, qname, dns.TypeA, dns.RcodeSuccess, tt.answer, nil, nil)
			assertCheck(t, checkTTL(86400, resp), tt.ok)
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
	tc = dnsCase{qname: "example.test.", qtype: dns.TypeTXT, tcp: true, edns: ednsOPT{udpSize: 512, version: 1}, truncated: true}
	if got, want := tc.query(toNameServer), (dnsQuery{name: "example.test.", qtype: dns.TypeTXT, qclass: dns.ClassINET, tcp: true, edns: ednsOPT{udpSize: 512, version: 1}, truncated: true}); got != want {
		t.Errorf("query with transport and EDNS = %+v, want %+v", got, want)
	}
	tc = dnsCase{qname: "example.test.", qtype: dns.TypeTXT, checkTruncated: expectNoRecords}
	if got, want := tc.query(toNameServer), (dnsQuery{name: "example.test.", qtype: dns.TypeTXT, qclass: dns.ClassINET, followTruncation: true}); got != want {
		t.Errorf("query of a case that checks a truncated reply = %+v, want %+v", got, want)
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
	production, err := loadFlyTarget("../fly.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range []*target{production, capturedRigTarget(t)} {
		t.Run(tg.name, func(t *testing.T) {
			cases := authoritativeCases(tg)
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
