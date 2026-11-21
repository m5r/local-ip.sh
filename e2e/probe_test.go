package e2e

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// What the prober's numbers mean: one lost probe can be the network between the test and the server and proves nothing, and whether the process restarted is read from the machine's events, not from here. The prober is there to catch a server that goes silent while it stays up (a handler blocked while a challenge is published, for instance), which is why the lifecycle test fails only when the longest silence reaches proberSilenceLimit and otherwise just reports the totals.
const (
	proberInterval     = 250 * time.Millisecond
	proberTimeout      = time.Second
	proberSilenceLimit = 3 * time.Second
)

// probe is one query of the prober: when it was sent and whether the expected answer came back in time.
type probe struct {
	sent     time.Time
	answered bool
}

// longestSilence returns the longest time during which no probe was answered: from the sending of the first probe of a run of unanswered ones to the sending of the next answered probe, or to end when the run is the last. probes are in sending order.
func longestSilence(probes []probe, end time.Time) time.Duration {
	var longest time.Duration
	var runStart time.Time
	inRun := false
	for _, p := range probes {
		switch {
		case !p.answered && !inRun:
			runStart, inRun = p.sent, true
		case p.answered && inRun:
			longest = max(longest, p.sent.Sub(runStart))
			inRun = false
		}
	}
	if inRun {
		longest = max(longest, end.Sub(runStart))
	}
	return longest
}

func unansweredProbes(probes []probe) int {
	n := 0
	for _, p := range probes {
		if !p.answered {
			n++
		}
	}
	return n
}

// startProber sends a query for name (type A) to server every 250 milliseconds until stop is called, each on a socket of its own, with one second to be answered and no retry. A probe is answered when the reply is NOERROR with exactly one A record equal to want. stop waits for the probes in flight and returns all of them in sending order with end, the moment the prober stopped sending: no probe was sent after it. It is registered with t.Cleanup, so a test that fails early leaves nothing running, and calling it more than once is safe.
//
// Each probe runs in a goroutine of its own so that one waiting for its timeout does not delay the next: at most five are in flight. The existing exchange helper retries, which would hide exactly the silences this measures.
func startProber(t *testing.T, server netip.AddrPort, name string, want netip.Addr) (stop func() (probes []probe, end time.Time)) {
	t.Helper()
	fqdn := dns.Fqdn(name)
	address := server.String()

	var mu sync.Mutex
	var sent []*probe
	var inFlight sync.WaitGroup
	quit := make(chan struct{})
	loopDone := make(chan struct{})

	send := func() {
		p := &probe{sent: time.Now()}
		mu.Lock()
		sent = append(sent, p)
		mu.Unlock()
		inFlight.Go(func() {
			answered := probeOnce(address, fqdn, want)
			mu.Lock()
			p.answered = answered
			mu.Unlock()
		})
	}

	go func() {
		defer close(loopDone)
		ticker := time.NewTicker(proberInterval)
		defer ticker.Stop()
		send()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				send()
			}
		}
	}()

	var once sync.Once
	var result []probe
	var end time.Time
	stop = func() ([]probe, time.Time) {
		once.Do(func() {
			close(quit)
			<-loopDone
			// Read only once the scheduling goroutine has ended: before that it may be inside send, or its select may pick a tick that was ready alongside quit, and a probe would be sent after end.
			end = time.Now()
			inFlight.Wait()
			mu.Lock()
			defer mu.Unlock()
			result = make([]probe, len(sent))
			for i, p := range sent {
				result[i] = *p
			}
		})
		return result, end
	}
	t.Cleanup(func() { stop() })
	return stop
}

// probeOnce has its own deadline and ignores the test's context, so that stop can let the probes in flight finish instead of counting them as lost.
func probeOnce(address, fqdn string, want netip.Addr) bool {
	query := new(dns.Msg)
	query.SetQuestion(fqdn, dns.TypeA)
	query.RecursionDesired = false

	ctx, cancel := context.WithTimeout(context.Background(), proberTimeout)
	defer cancel()
	client := &dns.Client{Net: "udp", Timeout: proberTimeout}
	resp, _, err := client.ExchangeContext(ctx, query, address)
	if err != nil || resp.Rcode != dns.RcodeSuccess || checkQuestionEcho(resp, fqdn, dns.TypeA) != nil || len(resp.Answer) != 1 {
		return false
	}
	record, ok := resp.Answer[0].(*dns.A)
	if !ok {
		return false
	}
	got, ok := netip.AddrFromSlice(record.A)
	return ok && got.Unmap() == want
}

func TestLongestSilence(t *testing.T) {
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return start.Add(time.Duration(ms) * time.Millisecond) }
	probes := func(answered ...bool) []probe {
		ps := make([]probe, len(answered))
		for i, a := range answered {
			ps[i] = probe{sent: at(250 * i), answered: a}
		}
		return ps
	}
	end := at(10_000)

	tests := []struct {
		name   string
		probes []probe
		want   time.Duration
	}{
		{name: "no probe", probes: nil, want: 0},
		{name: "all answered", probes: probes(true, true, true, true), want: 0},
		{name: "one unanswered between two answered", probes: probes(true, false, true), want: 250 * time.Millisecond},
		{name: "run in the middle", probes: probes(true, false, false, false, true, false, true), want: 750 * time.Millisecond},
		{name: "run at the start", probes: probes(false, false, true, true), want: 500 * time.Millisecond},
		{name: "run at the end, measured to end", probes: probes(true, true, false, false), want: end.Sub(at(500))},
		{name: "longest of several runs", probes: probes(false, true, false, false, false, true, false, true), want: 750 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := longestSilence(tt.probes, end); got != tt.want {
				t.Errorf("longestSilence = %s, want %s", got, tt.want)
			}
		})
	}
}

type responderMode int

const (
	respondCorrectly responderMode = iota
	respondSilently
	respondWithOtherAddress
	respondLate
)

// startResponder answers A queries on a loopback port of its own, behaving for the n-th query it receives (counting from 1) as mode(n) says. received is signalled with n after each query has been handled.
func startResponder(t *testing.T, want, other netip.Addr, mode func(n int) responderMode) (netip.AddrPort, *atomic.Int32, <-chan int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	var count atomic.Int32
	received := make(chan int, 64)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(buf[:n]); err != nil || len(query.Question) != 1 {
				continue
			}
			number := int(count.Add(1))
			reply := new(dns.Msg)
			reply.SetReply(query)
			answer := want
			if mode(number) == respondWithOtherAddress {
				answer = other
			}
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   answer.AsSlice(),
			}}
			packed, err := reply.Pack()
			if err != nil {
				t.Errorf("packing reply: %v", err)
				return
			}
			switch mode(number) {
			case respondSilently:
			case respondLate:
				time.AfterFunc(300*time.Millisecond, func() { conn.WriteTo(packed, from) })
			default:
				conn.WriteTo(packed, from)
			}
			select {
			case received <- number:
			default:
			}
		}
	}()
	return netip.MustParseAddrPort(conn.LocalAddr().String()), &count, received
}

func TestProber(t *testing.T) {
	want := netip.MustParseAddr("10.0.0.1")
	other := netip.MustParseAddr("10.0.0.2")
	const lateFrom = 8
	mode := func(n int) responderMode {
		switch {
		case n == 3 || n == 4:
			return respondSilently
		case n == 5 || n == 6:
			return respondWithOtherAddress
		case n >= lateFrom:
			return respondLate
		default:
			return respondCorrectly
		}
	}
	server, count, received := startResponder(t, want, other, mode)

	stop := startProber(t, server, "10-0-0-1.example.test", want)

	deadline := time.After(10 * time.Second)
	for waiting := true; waiting; {
		select {
		case n := <-received:
			waiting = n < lateFrom
		case <-deadline:
			t.Fatalf("the responder received %d queries in 10 seconds, want %d", count.Load(), lateFrom)
		}
	}

	probes, end := stop()
	again, againEnd := stop()

	if len(probes) < lateFrom {
		t.Fatalf("stop returned %d probes, want at least %d", len(probes), lateFrom)
	}
	if got := int(count.Load()); got != len(probes) {
		t.Errorf("stop returned %d probes, the responder received %d queries", len(probes), got)
	}
	for i := 1; i < len(probes); i++ {
		if !probes[i].sent.After(probes[i-1].sent) {
			t.Errorf("probe %d was sent at %s, not after probe %d at %s", i+1, probes[i].sent, i, probes[i-1].sent)
		}
	}
	if end.Before(probes[len(probes)-1].sent) {
		t.Errorf("end %s is before the last probe was sent at %s", end, probes[len(probes)-1].sent)
	}
	if got := unansweredProbes(probes); got != 4 {
		t.Errorf("%d probes unanswered, want 4 (two without reply, two with another address)", got)
	}
	if !probes[len(probes)-1].answered {
		t.Error("the last probe, answered late while stop was called, is unanswered: stop did not wait for the probes in flight")
	}
	if len(again) != len(probes) || !againEnd.Equal(end) {
		t.Errorf("second stop returned %d probes ending at %s, want the %d of the first ending at %s", len(again), againEnd, len(probes), end)
	}
	for i := range again {
		if again[i] != probes[i] {
			t.Errorf("second stop returned probe %d as %+v, first returned %+v", i+1, again[i], probes[i])
		}
	}
}
