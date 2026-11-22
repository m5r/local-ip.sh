package xip

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func writeZoneFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zone")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectReferral(t *testing.T, resp *dns.Msg) {
	t.Helper()
	wantNS := rrStrings(t,
		"sub.example.test. 300 IN NS ns1.sub.example.test.",
		"sub.example.test. 300 IN NS ns.other.test.",
	)
	wantGlue := rrStrings(t,
		"ns1.sub.example.test. 300 IN A 192.0.2.1",
		"ns1.sub.example.test. 300 IN AAAA 2001:db8::1",
	)

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if resp.Authoritative {
		t.Error("AA flag is set, want it clear on a referral")
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers, want none", len(resp.Answer))
	}
	if got := stringsOf(resp.Ns); !slices.Equal(got, wantNS) {
		t.Errorf("authority = %q, want %q", got, wantNS)
	}
	if got := stringsOf(resp.Extra); !slices.Equal(got, wantGlue) {
		t.Errorf("additional = %q, want %q", got, wantGlue)
	}
	if t.Failed() {
		t.Logf("response:\n%s", resp)
	}
}

// expectNoDataAtExampleTest checks the NODATA form of a negative answer for the zone example.test, the answer a DS query at a cut gets: the parent side of a cut answers for DS, and this zone has no DS records.
func expectNoDataAtExampleTest(t *testing.T, resp *dns.Msg) {
	t.Helper()
	expectNoData(t, resp, "example.test.", 300)
}

func expectDashedAnswer(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.Authoritative {
		t.Error("AA flag is clear, want it set")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want exactly 1:\n%s", len(resp.Answer), resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.0.0.1" {
		t.Errorf("answer = %q, want A 10.0.0.1", resp.Answer[0])
	}
}

func TestReferrals(t *testing.T) {
	zoneFile := writeZoneFile(t, `; sub is served elsewhere
sub NS ns1.sub
sub NS ns.other.test.
ns1.sub A 192.0.2.1
ns1.sub AAAA 2001:db8::1
`)
	address := startTestServer(t,
		WithDomain("example.test"),
		WithEmail("admin@example.test"),
		WithNameServers([]string{"192.0.2.10", "192.0.2.11"}),
		WithZoneFile(zoneFile),
	)

	tests := []struct {
		name   string
		qname  string
		qtype  uint16
		expect func(*testing.T, *dns.Msg)
	}{
		{name: "cut NS", qname: "sub.example.test.", qtype: dns.TypeNS, expect: expectReferral},
		{name: "name below the cut A", qname: "www.sub.example.test.", qtype: dns.TypeA, expect: expectReferral},
		{name: "dashed address below the cut A", qname: "10-0-0-1.sub.example.test.", qtype: dns.TypeA, expect: expectReferral},
		{name: "ACME challenge below the cut TXT", qname: "_acme-challenge.sub.example.test.", qtype: dns.TypeTXT, expect: expectReferral},
		{name: "DS strictly below the cut", qname: "a.b.sub.example.test.", qtype: dns.TypeDS, expect: expectReferral},
		{name: "cut ANY", qname: "sub.example.test.", qtype: dns.TypeANY, expect: expectReferral},
		{name: "glue name A", qname: "ns1.sub.example.test.", qtype: dns.TypeA, expect: expectReferral},
		{name: "glue name AAAA", qname: "ns1.sub.example.test.", qtype: dns.TypeAAAA, expect: expectReferral},
		{name: "mixed-case cut NS", qname: "SuB.ExAmPlE.TeSt.", qtype: dns.TypeNS, expect: expectReferral},
		{name: "DS at the cut is the zone's NODATA", qname: "sub.example.test.", qtype: dns.TypeDS, expect: expectNoDataAtExampleTest},
		{name: "mixed-case DS at the cut is the zone's NODATA", qname: "SuB.ExAmPlE.TeSt.", qtype: dns.TypeDS, expect: expectNoDataAtExampleTest},
		{name: "dashed address outside the cut", qname: "10-0-0-1.example.test.", qtype: dns.TypeA, expect: expectDashedAnswer},
		{name: "sibling sharing a suffix is the zone's NODATA, not a referral", qname: "xsub.example.test.", qtype: dns.TypeA, expect: expectNoDataAtExampleTest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := queryTestServer(t, address, tt.qname, tt.qtype)
			if len(resp.Question) != 1 || resp.Question[0].Name != tt.qname {
				t.Errorf("question section = %v, want it to echo %q byte-for-byte", resp.Question, tt.qname)
			}
			tt.expect(t, resp)
		})
	}
}

func TestNewXipRejectsBadZoneFile(t *testing.T) {
	tests := []struct {
		name     string
		zoneFile func(t *testing.T) string
	}{
		{
			name:     "missing file",
			zoneFile: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.zone") },
		},
		{
			name:     "invalid file",
			zoneFile: func(t *testing.T) string { return writeZoneFile(t, "sub PTR other.test.\n") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.zoneFile(t)
			xip, err := NewXip(
				WithDomain("bad-zone-file.test"),
				WithEmail("admin@bad-zone-file.test"),
				WithNameServers([]string{"192.0.2.10"}),
				WithZoneFile(path),
			)
			if err == nil {
				t.Fatal("NewXip succeeded, want an error")
			}
			if xip != nil {
				t.Error("NewXip returned a server together with an error")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not contain the path %q", err, path)
			}
		})
	}
}

func TestNewXipWithoutZoneFile(t *testing.T) {
	address := startTestServer(t,
		WithDomain("no-zone-file.test"),
		WithEmail("admin@no-zone-file.test"),
		WithNameServers([]string{"192.0.2.10"}),
	)

	expectDashedAnswer(t, queryTestServer(t, address, "10-0-0-1.sub.no-zone-file.test.", dns.TypeA))
}

// TestFailedNewXipLeavesRunningInstanceAnswering shows that building an instance touches nothing an instance already serving the same domain answers from.
func TestFailedNewXipLeavesRunningInstanceAnswering(t *testing.T) {
	const domain = "kept-registration.test"
	address := startTestServer(t,
		WithDomain(domain),
		WithEmail("admin@"+domain),
		WithNameServers([]string{"192.0.2.10"}),
	)

	_, err := NewXip(
		WithDomain(domain),
		WithEmail("admin@"+domain),
		WithNameServers([]string{"192.0.2.99"}),
		WithZoneFile(writeZoneFile(t, "sub NS ns1.sub\n")),
	)
	if err == nil {
		t.Fatal("NewXip succeeded with an invalid zone file, want an error")
	}

	resp := queryTestServer(t, address, "ns1."+domain+".", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want exactly 1:\n%s", len(resp.Answer), resp)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.10" {
		t.Errorf("answer = %q, want A 192.0.2.10 from the healthy server", resp.Answer[0])
	}
}

// TestConcurrentReferrals serves many referrals at once from the same stored records, so the race
// detector sees any write to them or to a backing array shared between responses.
func TestConcurrentReferrals(t *testing.T) {
	zoneFile := writeZoneFile(t, "sub NS ns1.sub\nns1.sub A 192.0.2.1\n")
	address := startTestServer(t,
		WithDomain("concurrent.test"),
		WithEmail("admin@concurrent.test"),
		WithNameServers([]string{"192.0.2.10"}),
		WithZoneFile(zoneFile),
	)

	const queries = 32
	errs := make(chan error, queries)
	for i := range queries {
		go func() {
			query := new(dns.Msg)
			query.SetQuestion(fmt.Sprintf("q%d.sub.concurrent.test.", i), dns.TypeA)
			client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			resp, _, err := client.ExchangeContext(t.Context(), query, address)
			switch {
			case err != nil:
				errs <- err
			case resp.Authoritative || len(resp.Ns) != 1 || len(resp.Extra) != 1:
				errs <- fmt.Errorf("not the expected referral:\n%s", resp)
			default:
				errs <- nil
			}
		}()
	}
	for range queries {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// TestReferralDoesNotShareStoredRecords guards the stored delegation: replies are packed concurrently, so a reply that held a stored record or shared a backing array with the stored slices could let one reply change what another sends.
func TestReferralDoesNotShareStoredRecords(t *testing.T) {
	xip, err := NewXip(
		WithDomain("shared-slices.test"),
		WithEmail("admin@shared-slices.test"),
		WithNameServers([]string{"192.0.2.10"}),
		WithZoneFile(writeZoneFile(t, "sub NS ns1.sub\nns1.sub A 192.0.2.1\n")),
	)
	if err != nil {
		t.Fatal(err)
	}
	stored := xip.zone.cuts.cuts["sub.shared-slices.test."]

	writer := &recordingWriter{}
	xip.handleDnsRequest(writer, newQuery("www.sub.shared-slices.test.", dns.TypeA))
	message := writer.written

	if message == nil || len(message.Ns) != 1 || len(message.Extra) != 1 {
		t.Fatalf("not the expected referral:\n%s", message)
	}
	if &message.Ns[0] == &stored.nameServers[0] || message.Ns[0] == stored.nameServers[0] {
		t.Error("the authority section shares the stored name server record or its backing array")
	}
	if &message.Extra[0] == &stored.glue[0] || message.Extra[0] == stored.glue[0] {
		t.Error("the additional section shares the stored glue record or its backing array")
	}
}

func TestReferralForCutSpelledWithEscapes(t *testing.T) {
	address := startTestServer(t,
		WithDomain("escaped-cut.test"),
		WithEmail("admin@escaped-cut.test"),
		WithNameServers([]string{"192.0.2.10"}),
		WithZoneFile(writeZoneFile(t, `\115ub NS ns1.\115ub`+"\n"+`ns1.sub A 192.0.2.1`+"\n")),
	)

	for _, qname := range []string{"sub.escaped-cut.test.", "www.SUB.escaped-cut.test."} {
		t.Run(qname, func(t *testing.T) {
			resp := queryTestServer(t, address, qname, dns.TypeA)
			want := rrStrings(t, "sub.escaped-cut.test. 300 IN NS ns1.sub.escaped-cut.test.")
			if resp.Authoritative || len(resp.Answer) != 0 || !slices.Equal(stringsOf(resp.Ns), want) {
				t.Errorf("want a referral with authority %q, received:\n%s", want, resp)
			}
		})
	}
}

func TestNewXipRejectsGlueAtOwnAddress(t *testing.T) {
	path := writeZoneFile(t, "sub NS ns1.sub\nns1.sub A 192.0.2.11\n")
	_, err := NewXip(
		WithDomain("own-address.test"),
		WithEmail("admin@own-address.test"),
		WithNameServers([]string{"192.0.2.10", "192.0.2.11"}),
		WithZoneFile(path),
	)
	if err == nil {
		t.Fatal("NewXip succeeded with glue pointing back at its own name server, want an error")
	}
	for _, want := range []string{path, "ns1.sub.own-address.test.", "192.0.2.11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
