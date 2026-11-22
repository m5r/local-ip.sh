package xip

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	challengeTestDomain = "local-ip.sh"
	challengeTestName   = "_acme-challenge.local-ip.sh."
)

func newChallengeXip(t *testing.T) *Xip {
	t.Helper()
	xip, err := NewXip(
		WithDomain(challengeTestDomain),
		WithEmail("admin@"+challengeTestDomain),
		WithNameServers([]string{"192.0.2.10", "192.0.2.11"}),
	)
	if err != nil {
		t.Fatalf("NewXip: %v", err)
	}
	return xip
}

func expectEmptyChallengeAnswer(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.Authoritative {
		t.Error("AA flag is clear, want it set")
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers, want none", len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("got %d authority records, want one SOA:\n%s", len(resp.Ns), resp)
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority record = %q, want an SOA", resp.Ns[0])
	}
	if soa.Hdr.Ttl != 0 {
		t.Errorf("SOA TTL = %d, want 0", soa.Hdr.Ttl)
	}
	if want := challengeTestDomain + "."; soa.Hdr.Name != want {
		t.Errorf("SOA owner = %q, want the zone apex %q", soa.Hdr.Name, want)
	}
	if t.Failed() {
		t.Logf("response:\n%s", resp)
	}
}

// expectChallengeValues checks a TXT answer at the challenge name: one record per value, in the order given, each with TTL 0 and the owner name as asked.
func expectChallengeValues(t *testing.T, resp *dns.Msg, qname string, values ...string) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if !resp.Authoritative {
		t.Error("AA flag is clear, want it set")
	}
	if len(resp.Answer) != len(values) {
		t.Fatalf("got %d answers, want %d:\n%s", len(resp.Answer), len(values), resp)
	}
	for i, value := range values {
		txt, ok := resp.Answer[i].(*dns.TXT)
		if !ok {
			t.Errorf("answer %d = %q, want a TXT record", i, resp.Answer[i])
			continue
		}
		if got := strings.Join(txt.Txt, ""); got != value {
			t.Errorf("answer %d = %q, want %q", i, got, value)
		}
		if txt.Hdr.Ttl != 0 {
			t.Errorf("answer %d TTL = %d, want 0", i, txt.Hdr.Ttl)
		}
		if txt.Hdr.Name != qname {
			t.Errorf("answer %d owner = %q, want %q as asked", i, txt.Hdr.Name, qname)
		}
	}
	if t.Failed() {
		t.Logf("response:\n%s", resp)
	}
}

func TestChallengeRecords(t *testing.T) {
	xip := newChallengeXip(t)
	address := serveTestXip(t, xip)
	const (
		first  = "first-value-Qx9"
		second = "a-second-value"
	)

	t.Run("empty set", func(t *testing.T) {
		expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT))
	})

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA} {
		t.Run(dns.TypeToString[qtype]+" before publication", func(t *testing.T) {
			expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, qtype))
		})
	}

	t.Run("one value published without trailing dot", func(t *testing.T) {
		if err := xip.AddChallenge(strings.TrimSuffix(challengeTestName, "."), first); err != nil {
			t.Fatalf("AddChallenge: %v", err)
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, first)
	})

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCAA} {
		t.Run(dns.TypeToString[qtype]+" after publication", func(t *testing.T) {
			expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, qtype))
			expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, first)
		})
	}

	t.Run("adding the same value twice keeps one copy", func(t *testing.T) {
		if err := xip.AddChallenge(challengeTestName, first); err != nil {
			t.Fatalf("AddChallenge: %v", err)
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, first)
	})

	t.Run("two values sorted", func(t *testing.T) {
		if err := xip.AddChallenge(challengeTestName, second); err != nil {
			t.Fatalf("AddChallenge: %v", err)
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, second, first)
	})

	t.Run("mixed-case question", func(t *testing.T) {
		const qname = "_ACME-Challenge.Local-IP.SH."
		resp := queryTestServer(t, address, qname, dns.TypeTXT)
		if len(resp.Question) != 1 || resp.Question[0].Name != qname {
			t.Errorf("question section = %v, want it to echo %q byte-for-byte", resp.Question, qname)
		}
		expectChallengeValues(t, resp, qname, second, first)
	})

	t.Run("names outside the challenge name", func(t *testing.T) {
		for _, name := range []string{
			"local-ip.sh.",
			"_acme-challenge.other.test.",
			"x._acme-challenge.local-ip.sh.",
			"_acme-challenge.sub.local-ip.sh",
			"",
		} {
			for method, call := range map[string]func(string, string) error{
				"AddChallenge":    xip.AddChallenge,
				"RemoveChallenge": xip.RemoveChallenge,
			} {
				err := call(name, "outsider")
				want := fmt.Sprintf("xip: %q is not the challenge name of this zone (%s)", name, challengeTestName)
				if err == nil || err.Error() != want {
					t.Errorf("%s(%q) = %v, want %q", method, name, err, want)
				}
			}
		}
		if err := xip.RemoveChallenge("_acme-challenge.other.test.", first); err == nil {
			t.Error("RemoveChallenge accepted a name outside the challenge name")
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, second, first)
	})

	t.Run("removing one value leaves the other", func(t *testing.T) {
		if err := xip.RemoveChallenge(challengeTestName, second); err != nil {
			t.Fatalf("RemoveChallenge: %v", err)
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, first)
	})

	t.Run("removing a value that is not published", func(t *testing.T) {
		if err := xip.RemoveChallenge(challengeTestName, "never-published"); err != nil {
			t.Fatalf("RemoveChallenge: %v", err)
		}
		expectChallengeValues(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT), challengeTestName, first)
	})

	t.Run("removing the last value", func(t *testing.T) {
		if err := xip.RemoveChallenge(strings.ToUpper(challengeTestName), first); err != nil {
			t.Fatalf("RemoveChallenge: %v", err)
		}
		expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT))
	})

	// The negative answer is the zone's NODATA, whose SOA record is owned by the apex, not by the question name.
	t.Run("TXT names without records get the zone's NODATA", func(t *testing.T) {
		for _, qname := range []string{"local-ip.sh.", "nope.local-ip.sh."} {
			expectNoData(t, queryTestServer(t, address, qname, dns.TypeTXT), challengeTestDomain+".", 3600)
		}
	})

	t.Run("ANY with a value published is the HINFO record with TTL 0", func(t *testing.T) {
		if err := xip.AddChallenge(challengeTestName, first); err != nil {
			t.Fatalf("AddChallenge: %v", err)
		}
		t.Cleanup(func() {
			if err := xip.RemoveChallenge(challengeTestName, first); err != nil {
				t.Errorf("RemoveChallenge: %v", err)
			}
		})
		resp := queryTestServer(t, address, challengeTestName, dns.TypeANY)
		want := rrStrings(t, challengeTestName+` 0 IN HINFO "RFC8482" ""`)
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || !slices.Equal(stringsOf(resp.Answer), want) || len(resp.Ns) != 0 {
			t.Errorf("want NOERROR, AA and answer %q, received:\n%s", want, resp)
		}
	})

	t.Run("ANY without a value published is NODATA with TTL 0", func(t *testing.T) {
		expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, dns.TypeANY))
	})
}

func TestChallengeRecordsConcurrent(t *testing.T) {
	xip := newChallengeXip(t)
	address := serveTestXip(t, xip)

	const (
		writers           = 8
		readers           = 4
		queriesPerReader  = 50
		minimumIterations = 20
	)
	// Writers churn until every reader has finished its queries, so the reads overlap the writes however the goroutines are scheduled.
	stop := make(chan struct{})
	var writersDone sync.WaitGroup
	for w := range writers {
		writersDone.Go(func() {
			for i := 0; ; i++ {
				if i >= minimumIterations {
					select {
					case <-stop:
						return
					default:
					}
				}
				value := fmt.Sprintf("writer-%d-value-%d", w, i)
				if err := xip.AddChallenge(challengeTestName, value); err != nil {
					t.Errorf("AddChallenge: %v", err)
					return
				}
				if err := xip.RemoveChallenge(challengeTestName, value); err != nil {
					t.Errorf("RemoveChallenge: %v", err)
					return
				}
			}
		})
	}

	var readersDone sync.WaitGroup
	for range readers {
		readersDone.Go(func() {
			client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
			for range queriesPerReader {
				query := new(dns.Msg)
				query.SetQuestion(challengeTestName, dns.TypeTXT)
				resp, _, err := client.ExchangeContext(t.Context(), query, address)
				if err != nil {
					t.Errorf("querying %s: %v", challengeTestName, err)
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
				}
				for _, rr := range resp.Answer {
					if txt, ok := rr.(*dns.TXT); !ok || txt.Hdr.Ttl != 0 {
						t.Errorf("answer %q, want TXT records with TTL 0", rr)
					}
				}
			}
		})
	}

	readersDone.Wait()
	close(stop)
	writersDone.Wait()

	expectEmptyChallengeAnswer(t, queryTestServer(t, address, challengeTestName, dns.TypeTXT))
}
