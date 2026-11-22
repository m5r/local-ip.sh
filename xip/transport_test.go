package xip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The limits a reply must fit in: 512 octets over UDP without EDNS, at most 1232 with it, 65535 over TCP.
const (
	classicUDPLimit = 512
	ednsUDPLimit    = 1232
	tcpLimit        = 65535
)

// maxReplyWithoutOPT is the largest reply the size checks accept: one that fits in a DNS message once the server's OPT record of 11 octets is added.
const maxReplyWithoutOPT = tcpLimit - 11

// txtSet declares count TXT records at label, each a string of length octets of its own letter, and returns the zone file lines and the records as the server serves them to a question for qname.
func txtSet(label string, count, length int) (lines string, records []string) {
	var b strings.Builder
	for i := range count {
		value := strings.Repeat(string(rune('a'+i)), length)
		fmt.Fprintf(&b, "%s TXT %q\n", label, value)
		records = append(records, fmt.Sprintf("{q} 300 IN TXT %q", value))
	}
	return b.String(), records
}

var (
	// smallLines makes a reply of about 250 octets, mediumLines one between 512 and 1232 octets, largeLines one of more than 1232.
	smallLines, smallRecords   = txtSet("small", 1, 200)
	mediumLines, mediumRecords = txtSet("medium", 4, 200)
	largeLines, largeRecords   = txtSet("large", 12, 250)
	transportZoneFile          = smallLines + mediumLines + largeLines
)

func dialTCP(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("connecting to %s over TCP: %v", address, err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// tcpFrame is packet with the two-octet length that precedes a DNS message over TCP.
func tcpFrame(packet []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
}

func writeTCPMessage(t *testing.T, conn net.Conn, packet []byte) {
	t.Helper()
	if _, err := conn.Write(tcpFrame(packet)); err != nil {
		t.Fatalf("writing to %s: %v", conn.RemoteAddr(), err)
	}
}

func readTCPMessage(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatalf("reading the length of a reply from %s: %v", conn.RemoteAddr(), err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading a reply from %s: %v", conn.RemoteAddr(), err)
	}
	return reply
}

// exchangeRawOver sends packet over network, "udp" or "tcp", on a connection of its own and returns the octets of the reply.
func exchangeRawOver(t *testing.T, network, address string, packet []byte) []byte {
	t.Helper()
	if network == "udp" {
		return exchangeRaw(t, address, packet)
	}
	conn := dialTCP(t, address)
	writeTCPMessage(t, conn, packet)
	return readTCPMessage(t, conn)
}

func exchangeOver(t *testing.T, network, address string, request *dns.Msg) *dns.Msg {
	t.Helper()
	_, resp := exchangeMeasured(t, network, address, request)
	return resp
}

// exchangeMeasured returns the length of the reply in octets together with the reply.
func exchangeMeasured(t *testing.T, network, address string, request *dns.Msg) (int, *dns.Msg) {
	t.Helper()
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply := exchangeRawOver(t, network, address, packet)
	resp := new(dns.Msg)
	if err := resp.Unpack(reply); err != nil {
		t.Fatalf("unpacking the reply over %s: %v", network, err)
	}
	if resp.Id != request.Id {
		t.Fatalf("reply id %d, want %d", resp.Id, request.Id)
	}
	return len(reply), resp
}

// limitFor is the size a reply must fit in over network for a query whose OPT record advertises size, 0 for a query without one.
func limitFor(network string, size uint16) int {
	switch {
	case network == "tcp":
		return tcpLimit
	case size == 0:
		return classicUDPLimit
	}
	return min(max(int(size), classicUDPLimit), ednsUDPLimit)
}

// optRecords returns the OPT records of a section.
func optRecords(section []dns.RR) []*dns.OPT {
	var opts []*dns.OPT
	for _, rr := range section {
		if opt, ok := rr.(*dns.OPT); ok {
			opts = append(opts, opt)
		}
	}
	return opts
}

// checkReplyOPT checks the OPT record of a reply: none for a query without one, otherwise exactly one that advertises 1232 octets, has version 0, the query's DO bit and no options.
func checkReplyOPT(t *testing.T, resp *dns.Msg, query *dns.OPT) {
	t.Helper()
	opts := optRecords(resp.Extra)
	if query == nil {
		if len(opts) != 0 {
			t.Errorf("a query without an OPT record got %d in the reply:\n%s", len(opts), resp)
		}
		return
	}
	if len(opts) != 1 {
		t.Fatalf("the reply has %d OPT records, want 1:\n%s", len(opts), resp)
	}
	opt := opts[0]
	if opt.Hdr.Name != "." || opt.UDPSize() != ednsUDPLimit || opt.Version() != 0 || opt.Do() != query.Do() || len(opt.Option) != 0 {
		t.Errorf("OPT record: name %q, UDP size %d, version %d, DO %v, %d options; want ., %d, 0, DO %v, no options", opt.Hdr.Name, opt.UDPSize(), opt.Version(), opt.Do(), len(opt.Option), ednsUDPLimit, query.Do())
	}
	if opt != resp.Extra[len(resp.Extra)-1] {
		t.Errorf("the OPT record is not the last record of the additional section:\n%s", resp)
	}
}

func TestReplyLimits(t *testing.T) {
	_, address := startExampleServer(t, transportZoneFile)
	sets := map[string][]string{"small": smallRecords, "medium": mediumRecords, "large": largeRecords}

	tests := []struct {
		name    string
		network string
		label   string
		// size is what the query's OPT record advertises, 0 for a query without one.
		size  uint16
		whole bool
	}{
		{name: "a reply under 512 octets is whole over UDP without EDNS", network: "udp", label: "small", whole: true},
		{name: "a reply over 512 octets is truncated over UDP without EDNS", network: "udp", label: "medium"},
		{name: "a reply under 1232 octets is whole over UDP with EDNS 1232", network: "udp", label: "medium", size: 1232, whole: true},
		{name: "a reply is truncated over UDP when the query advertises less than it needs", network: "udp", label: "medium", size: 700},
		{name: "an advertised size below 512 counts as 512", network: "udp", label: "small", size: 100, whole: true},
		{name: "an advertised size below 512 truncates at 512", network: "udp", label: "medium", size: 100},
		{name: "a reply over 1232 octets is truncated over UDP even when the query advertises 4096", network: "udp", label: "large", size: 4096},
		{name: "a reply over 1232 octets is truncated over UDP without EDNS", network: "udp", label: "large"},
		{name: "a reply over 1232 octets is whole over TCP without EDNS", network: "tcp", label: "large", whole: true},
		{name: "a reply over 1232 octets is whole over TCP when the query advertises 512", network: "tcp", label: "large", size: 512, whole: true},
		{name: "a reply over 512 octets is whole over TCP without EDNS", network: "tcp", label: "medium", whole: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, do := range []bool{false, true} {
				if do && tt.size == 0 {
					continue
				}
				qname := capitalise(tt.label+"."+exampleApex, 5)
				request := ask(qname, dns.TypeTXT)
				if tt.size != 0 {
					request.SetEdns0(tt.size, do)
				}
				length, resp := exchangeMeasured(t, tt.network, address, request)

				if limit := limitFor(tt.network, tt.size); length > limit {
					t.Errorf("the reply takes %d octets, more than the limit of %d", length, limit)
				}
				if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative {
					t.Errorf("rcode %s, AA %v; want NOERROR and AA", dns.RcodeToString[resp.Rcode], resp.Authoritative)
				}
				if resp.Truncated == tt.whole {
					t.Errorf("TC = %v, want %v", resp.Truncated, !tt.whole)
				}
				full := expandRecords(t, sets[tt.label], qname)
				got := stringsOf(resp.Answer)
				switch {
				case tt.whole && !slices.Equal(got, full):
					t.Errorf("answer = %q, want the whole set %q", got, full)
				case !tt.whole && (len(got) >= len(full) || !slices.Equal(got, full[:len(got)])):
					t.Errorf("answer = %q, want the set cut after a whole record: %q", got, full)
				}
				if len(resp.Ns) != 0 {
					t.Errorf("authority = %q, want none", stringsOf(resp.Ns))
				}
				checkReplyOPT(t, resp, request.IsEdns0())
				if len(resp.Extra) != len(optRecords(resp.Extra)) {
					t.Errorf("additional = %q, want nothing but the OPT record", stringsOf(resp.Extra))
				}
			}
		})
	}
}

func TestReplyOPTForEveryRcode(t *testing.T) {
	_, address := startExampleServer(t, transportZoneFile)
	tests := []struct {
		name    string
		request func() *dns.Msg
		rcode   int
	}{
		{name: "an answer", request: func() *dns.Msg { return ask(exampleApex, dns.TypeSOA) }, rcode: dns.RcodeSuccess},
		{name: "NODATA", request: func() *dns.Msg { return ask("nope.example.test.", dns.TypeA) }, rcode: dns.RcodeSuccess},
		{name: "NXDOMAIN", request: func() *dns.Msg { return ask(nameOfWireLength(t, 255, exampleApex), dns.TypeA) }, rcode: dns.RcodeNameError},
		{name: "REFUSED", request: func() *dns.Msg { return ask("other.test.", dns.TypeA) }, rcode: dns.RcodeRefused},
		{name: "NOTIMP", request: func() *dns.Msg { return askWith(exampleApex, dns.TypeSOA, withOpcode(dns.OpcodeNotify)) }, rcode: dns.RcodeNotImplemented},
		{name: "FORMERR for class 0", request: func() *dns.Msg { return askWith(exampleApex, dns.TypeA, inClass(0)) }, rcode: dns.RcodeFormatError},
		{name: "FORMERR for two questions", request: func() *dns.Msg {
			request := ask(exampleApex, dns.TypeA)
			request.Question = append(request.Question, dns.Question{Name: "www.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			return request
		}, rcode: dns.RcodeFormatError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				for _, do := range []bool{false, true} {
					request := tt.request()
					request.SetEdns0(4096, do)
					resp := exchangeOver(t, network, address, request)
					if resp.Rcode != tt.rcode {
						t.Errorf("over %s with DO %v: rcode = %s, want %s", network, do, dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
					}
					checkReplyOPT(t, resp, request.IsEdns0())
				}

				request := tt.request()
				resp := exchangeOver(t, network, address, request)
				if resp.Rcode != tt.rcode {
					t.Errorf("over %s without EDNS: rcode = %s, want %s", network, dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
				}
				checkReplyOPT(t, resp, nil)
			}
		})
	}

	t.Run("the options of a query are ignored", func(t *testing.T) {
		request := ask(exampleApex, dns.TypeSOA)
		request.SetEdns0(1232, true)
		opt := request.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID}, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
		resp := exchangeOver(t, "udp", address, request)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Errorf("want NOERROR and the SOA record, received:\n%s", resp)
		}
		checkReplyOPT(t, resp, opt)
	})
}

// expectEDNSError checks a reply that holds the question, the OPT record of the server and nothing else, with AA clear.
func expectEDNSError(t *testing.T, resp, request *dns.Msg, rcode int) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Errorf("rcode = %d (%s), want %d", resp.Rcode, dns.RcodeToString[resp.Rcode], rcode)
	}
	if resp.Authoritative {
		t.Error("AA is set, want it clear")
	}
	if len(resp.Question) != 1 || resp.Question[0] != request.Question[0] {
		t.Errorf("question = %v, want %v", resp.Question, request.Question[:1])
	}
	if len(resp.Answer) != 0 || len(resp.Ns) != 0 || len(resp.Extra) != 1 {
		t.Errorf("want no record but one OPT record, received:\n%s", resp)
	}
	checkReplyOPT(t, resp, request.IsEdns0())
}

func TestEDNSErrors(t *testing.T) {
	_, address := startExampleServer(t, transportZoneFile)
	questions := []struct {
		name    string
		request func() *dns.Msg
	}{
		{name: "a question the zone answers", request: func() *dns.Msg { return ask(exampleApex, dns.TypeSOA) }},
		{name: "a name outside the zone", request: func() *dns.Msg { return ask("other.test.", dns.TypeA) }},
		{name: "a NOTIFY", request: func() *dns.Msg { return askWith(exampleApex, dns.TypeSOA, withOpcode(dns.OpcodeNotify)) }},
		{name: "a large answer", request: func() *dns.Msg { return ask("large.example.test.", dns.TypeTXT) }},
	}

	for _, question := range questions {
		t.Run("EDNS version 1 gets BADVERS for "+question.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				for _, do := range []bool{false, true} {
					request := question.request()
					request.SetEdns0(1232, do)
					request.IsEdns0().SetVersion(1)
					expectEDNSError(t, exchangeOver(t, network, address, request), request, dns.RcodeBadVers)
				}
			}
		})
		t.Run("two OPT records get FORMERR for "+question.name, func(t *testing.T) {
			for _, network := range []string{"udp", "tcp"} {
				request := question.request()
				request.SetEdns0(4096, false)
				second := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
				second.SetUDPSize(1232)
				second.SetDo()
				request.Extra = append(request.Extra, second)
				expectEDNSError(t, exchangeOver(t, network, address, request), request, dns.RcodeFormatError)
			}
		})
	}
}

func TestMessagesTheLibraryRefused(t *testing.T) {
	_, address := startExampleServer(t, transportZoneFile)
	notImp := answerWant{rcode: dns.RcodeNotImplemented}

	for _, opcode := range []int{dns.OpcodeIQuery, dns.OpcodeStatus, 3, dns.OpcodeUpdate, 15} {
		t.Run(fmt.Sprintf("opcode %d gets NOTIMP from the handler", opcode), func(t *testing.T) {
			exchangeAndCheck(t, address, askWith(exampleApex, dns.TypeSOA, withOpcode(opcode), withRD), notImp)
		})
	}
	t.Run("an UPDATE with records in its sections gets NOTIMP", func(t *testing.T) {
		request := askWith(exampleApex, dns.TypeSOA, withOpcode(dns.OpcodeUpdate), withAuthority(t, "www.example.test. 300 IN A 192.0.2.1"), withAuthority(t, "www.example.test. 300 IN A 192.0.2.2"))
		exchangeAndCheck(t, address, request, notImp)
	})

	t.Run("records in the answer, authority and additional sections of a query are ignored", func(t *testing.T) {
		request := askWith("small.example.test.", dns.TypeTXT, withAuthority(t, exampleSOA), withAuthority(t, "example.test. 300 IN NS ns9.example.test."))
		request.Answer = []dns.RR{mustRR(t, "small.example.test. 300 IN TXT \"forged\""), mustRR(t, "small.example.test. 300 IN TXT \"forged too\"")}
		request.Extra = []dns.RR{mustRR(t, "a.example.test. 300 IN A 192.0.2.1"), mustRR(t, "b.example.test. 300 IN A 192.0.2.2"), mustRR(t, "c.example.test. 300 IN A 192.0.2.3")}
		exchangeAndCheck(t, address, request, positive(smallRecords...))
	})
}

func TestResponsesGetNoReply(t *testing.T) {
	_, address := startExampleServer(t, transportZoneFile)
	response := ask(exampleApex, dns.TypeSOA)
	response.Id = 0x1111
	response.Response = true
	responsePacket, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	query := ask(exampleApex, dns.TypeSOA)
	query.Id = 0x2222
	queryPacket, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("over TCP the query after a response gets the first reply", func(t *testing.T) {
		conn := dialTCP(t, address)
		writeTCPMessage(t, conn, responsePacket)
		writeTCPMessage(t, conn, queryPacket)
		resp := new(dns.Msg)
		if err := resp.Unpack(readTCPMessage(t, conn)); err != nil {
			t.Fatal(err)
		}
		if resp.Id != query.Id {
			t.Errorf("the first reply has id %#x, want %#x: the response was answered", resp.Id, query.Id)
		}
	})

	t.Run("over UDP only the query is answered", func(t *testing.T) {
		conn, err := net.Dial("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for _, packet := range [][]byte{responsePacket, queryPacket} {
			if _, err := conn.Write(packet); err != nil {
				t.Fatal(err)
			}
		}
		buf := make([]byte, dns.MaxMsgSize)
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("reading the reply to the query: %v", err)
		}
		if id := binary.BigEndian.Uint16(buf[:n]); id != query.Id {
			t.Fatalf("got a reply with id %#x, want %#x: the response was answered", id, query.Id)
		}
		// The query was answered, so a reply to the response would be on its way; waiting a little longer catches it if the handlers ran out of order.
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(buf); !isTimeout(err) {
			t.Errorf("got a second reply of %d octets (%v), want none", n, err)
		}
	})
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// TestZoneFileAnswerAtTheSizeLimit serves an answer that takes 65535 octets with the OPT record, the most a DNS message holds, and shows it arrives whole over TCP.
func TestZoneFileAnswerAtTheSizeLimit(t *testing.T) {
	content := fmt.Sprintf("big TXT \"%s\"\n", strings.Repeat("x", largestFittingTXTLength))
	_, address := startExampleServer(t, content)
	request := ask("BIG.EXAMPLE.TEST.", dns.TypeTXT)
	request.SetEdns0(1232, false)
	length, resp := exchangeMeasured(t, "tcp", address, request)
	if length != tcpLimit {
		t.Errorf("the reply takes %d octets, want %d", length, tcpLimit)
	}
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("TC %v and %d answers, want the whole answer", resp.Truncated, len(resp.Answer))
	}
	if txt, ok := resp.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != strings.Repeat("x", largestFittingTXTLength) {
		t.Errorf("the answer is not the TXT record of the zone file")
	}
	checkReplyOPT(t, resp, request.IsEdns0())
}

// acceptAsync calls Accept on l in a goroutine and returns the channel its result arrives on.
func acceptAsync(l net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	return accepted
}

func TestTCPListenerCapsConnections(t *testing.T) {
	const connectionCap = 2
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newTCPListener(inner, connectionCap)
	t.Cleanup(func() { listener.Close() })
	// The kernel completes these connections in its accept queue whether or not Accept is called.
	for range connectionCap + 2 {
		dialTCP(t, inner.Addr().String())
	}

	accepted := make([]net.Conn, connectionCap)
	for i := range accepted {
		select {
		case conn, ok := <-acceptAsync(listener):
			if !ok {
				t.Fatalf("Accept %d failed below the cap", i+1)
			}
			accepted[i] = conn
			t.Cleanup(func() { conn.Close() })
		case <-time.After(10 * time.Second):
			t.Fatalf("Accept %d did not return below the cap", i+1)
		}
	}

	waiting := acceptAsync(listener)
	select {
	case <-waiting:
		t.Fatalf("Accept returned with %d connections open, the cap", connectionCap)
	case <-time.After(200 * time.Millisecond):
	}

	// The connection the waiting Accept returns holds a slot until the whole test ends, so that the next subtest finds the cap reached again.
	parent := t
	t.Run("closing an accepted connection lets the waiting Accept return", func(t *testing.T) {
		accepted[0].Close()
		select {
		case conn, ok := <-waiting:
			if !ok {
				t.Fatal("the waiting Accept failed")
			}
			parent.Cleanup(func() { conn.Close() })
		case <-time.After(10 * time.Second):
			t.Fatal("the waiting Accept did not return after a connection was closed")
		}
	})

	t.Run("closing the same connection again frees no second slot", func(t *testing.T) {
		accepted[0].Close()
		select {
		case <-acceptAsync(listener):
			t.Fatal("Accept returned after a connection was closed twice: two slots were freed")
		case <-time.After(200 * time.Millisecond):
		}
	})
}

func TestTCPListenerReportsOnlyAcceptErrorsItDidNotCause(t *testing.T) {
	t.Run("the listener closed from outside", func(t *testing.T) {
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := newTCPListener(inner, 1)
		inner.Close()

		if _, err := listener.Accept(); err == nil {
			t.Fatal("Accept on a closed listener succeeded")
		}
		select {
		case err := <-listener.failed:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("reported %v, want the accept error", err)
			}
		default:
			t.Error("the accept error was not reported")
		}
	})

	t.Run("its own Close, with an Accept waiting for a slot", func(t *testing.T) {
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listener := newTCPListener(inner, 1)
		t.Cleanup(func() { listener.Close() })
		dialTCP(t, inner.Addr().String())
		dialTCP(t, inner.Addr().String())

		select {
		case conn, ok := <-acceptAsync(listener):
			if !ok {
				t.Fatal("Accept failed below the cap")
			}
			t.Cleanup(func() { conn.Close() })
		case <-time.After(10 * time.Second):
			t.Fatal("Accept did not return below the cap")
		}
		waiting := acceptAsync(listener)
		select {
		case <-waiting:
			t.Fatal("Accept returned with the cap reached")
		case <-time.After(200 * time.Millisecond):
		}

		listener.Close()
		select {
		case conn, ok := <-waiting:
			if ok {
				conn.Close()
				t.Fatal("the waiting Accept returned a connection after Close")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the waiting Accept did not return after Close")
		}
		select {
		case err := <-listener.failed:
			t.Errorf("Close was reported as the failure %v", err)
		default:
		}
	})

	t.Run("another error after its own Close", func(t *testing.T) {
		failure := errors.New("accept failed")
		listener := newTCPListener(failingListener{err: failure}, 1)
		listener.Close()

		if _, err := listener.Accept(); !errors.Is(err, failure) {
			t.Fatalf("Accept returned %v, want %v", err, failure)
		}
		select {
		case err := <-listener.failed:
			if !errors.Is(err, failure) {
				t.Errorf("reported %v, want %v", err, failure)
			}
		default:
			t.Error("an error that Close did not cause was not reported")
		}
	})
}

// failingListener fails every Accept with err, whether or not it has been closed.
type failingListener struct{ err error }

func (l failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (failingListener) Close() error                { return nil }
func (failingListener) Addr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestDeadlineConnWriteDeadline(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	conn := &deadlineConn{Conn: server, writeTimeout: 50 * time.Millisecond}

	// Nothing reads client, so a write on a synchronous pipe can only end at its deadline.
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("reply"))
		done <- err
	}()
	select {
	case err := <-done:
		if !isTimeout(err) {
			t.Fatalf("Write to a peer that never reads returned %v, want a timeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write to a peer that never reads did not return within 10 seconds")
	}

	if _, err := server.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("writing on the pipe after the failed write returned %v, want it closed", err)
	}
}

func TestServeReportsAcceptError(t *testing.T) {
	xip := newServeTestXip(t, "serve-accept.test")
	conn, listener := listenTestTransports(t)
	served := make(chan error, 1)
	go func() { served <- xip.Serve(t.Context(), conn, listener) }()

	client := dialTCP(t, conn.LocalAddr().String())
	packet, err := ask("ns1.serve-accept.test.", dns.TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	writeTCPMessage(t, client, packet)
	readTCPMessage(t, client)

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// The server keeps an idle connection for 8 seconds, so returning within 5 shows that Serve did not wait for it.
	select {
	case err := <-served:
		if err == nil || !strings.Contains(err.Error(), "over TCP") {
			t.Fatalf("Serve returned %v after its listener was closed from outside, want an error naming TCP", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5 seconds of an accept error while a client held a connection open")
	}
}
