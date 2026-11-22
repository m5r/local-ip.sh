package xip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// expectNoData checks the NODATA form of a negative answer: NOERROR, AA, no answer, the zone's SOA record owned by the apex alone in the authority section with the TTL given, nothing in the additional section.
func expectNoData(t *testing.T, resp *dns.Msg, apex string, ttl uint32) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 0 || len(resp.Extra) != 0 || len(resp.Ns) != 1 {
		t.Fatalf("want NOERROR, AA, no answer, one SOA record and no additional record, received:\n%s", resp)
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Name != apex || soa.Hdr.Ttl != ttl {
		t.Errorf("authority = %q, want the SOA record of %s with TTL %d", resp.Ns[0], apex, ttl)
	}
}

// startExampleServer serves the example configuration with the given zone file on a loopback socket.
func startExampleServer(t *testing.T, zoneFileContent string) (*Xip, string) {
	t.Helper()
	xip, err := NewXip(
		WithDomain(exampleDomain),
		WithEmail(exampleEmail),
		WithNameServers(exampleNameServers),
		WithZoneFile(writeZoneFile(t, zoneFileContent)),
	)
	if err != nil {
		t.Fatalf("NewXip: %v", err)
	}
	return xip, serveTestXip(t, xip)
}

// exchangeRaw sends packet to the server and returns the octets of its reply. It works below dns.Client, which cannot send a message that is not well formed.
func exchangeRaw(t *testing.T, address string, packet []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("sending to %s: %v", address, err)
	}
	reply := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("reading the reply from %s: %v", address, err)
	}
	return reply[:n]
}

// headerLength is the length of the fixed header of a DNS message, where the question section starts.
const headerLength = 12

// questionSectionLength is the number of octets of the question section of request in wire format.
func questionSectionLength(t *testing.T, request *dns.Msg) int {
	t.Helper()
	header := new(dns.Msg)
	header.Question = request.Question
	packed, err := header.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return len(packed) - headerLength
}

// checkReply compares a reply that came over UDP, or from the handler with a UDP address, with what the row wants: RCODE, the flags, the three sections and the size. qname replaces {q} in the expected records.
func checkReply(t *testing.T, reply []byte, request *dns.Msg, want answerWant, qname string) *dns.Msg {
	t.Helper()
	resp := new(dns.Msg)
	if err := resp.Unpack(reply); err != nil {
		t.Fatalf("unpacking the reply: %v", err)
	}
	size := uint16(0)
	if opt := request.IsEdns0(); opt != nil {
		size = opt.UDPSize()
	}
	if limit := limitFor("udp", size); len(reply) > limit {
		t.Errorf("the reply takes %d octets, more than the limit of %d over UDP", len(reply), limit)
	}
	if !resp.Response || resp.Id != request.Id || resp.Opcode != request.Opcode {
		t.Errorf("not a reply to the request: QR %v, id %d (sent %d), opcode %d (sent %d)", resp.Response, resp.Id, request.Id, resp.Opcode, request.Opcode)
	}
	if resp.Rcode != want.rcode {
		t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[want.rcode])
	}
	if resp.Authoritative != want.aa {
		t.Errorf("AA = %v, want %v", resp.Authoritative, want.aa)
	}
	if wantRD := request.RecursionDesired && request.Opcode == dns.OpcodeQuery; resp.RecursionDesired != wantRD {
		t.Errorf("RD = %v, want %v", resp.RecursionDesired, wantRD)
	}
	if resp.RecursionAvailable || resp.AuthenticatedData || resp.CheckingDisabled {
		t.Errorf("RA %v, AD %v, CD %v, want all clear", resp.RecursionAvailable, resp.AuthenticatedData, resp.CheckingDisabled)
	}
	sections := []struct {
		name string
		got  []dns.RR
		want []string
	}{
		{"answer", resp.Answer, want.answer},
		{"authority", resp.Ns, want.authority},
		{"additional", resp.Extra, want.additional},
	}
	if want.answerOctets != nil {
		checkAnswerOctets(t, "reply", reply, want.answerOctets, qname)
		sections = sections[1:]
	}
	for _, section := range sections {
		if got, want := stringsOf(section.got), expandRecords(t, section.want, qname); !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", section.name, got, want)
		}
	}
	return resp
}

// exchangeAndCheck sends a request with one complete question and checks the reply, its question section octet for octet included.
func exchangeAndCheck(t *testing.T, address string, request *dns.Msg, want answerWant) {
	t.Helper()
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply := exchangeRaw(t, address, packet)
	resp := checkReply(t, reply, request, want, request.Question[0].Name)
	end := headerLength + questionSectionLength(t, request)
	if len(resp.Question) != 1 || len(reply) < end || !bytes.Equal(reply[headerLength:end], packet[headerLength:end]) {
		t.Errorf("question section = %v, want the question as asked, octet for octet: %v", resp.Question, request.Question)
	}
	if t.Failed() {
		t.Logf("reply:\n%s", resp)
	}
}

// setChallenge leaves exactly values published at the challenge name, published in the order given.
func setChallenge(t *testing.T, xip *Xip, values []string) {
	t.Helper()
	xip.challengeMu.RLock()
	published := slices.Collect(maps.Keys(xip.challengeValues))
	xip.challengeMu.RUnlock()
	for _, value := range published {
		if err := xip.RemoveChallenge(xip.challengeName, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range values {
		if err := xip.AddChallenge(xip.challengeName, value); err != nil {
			t.Fatal(err)
		}
	}
}

type requestOption func(*dns.Msg)

func inClass(class uint16) requestOption {
	return func(m *dns.Msg) { m.Question[0].Qclass = class }
}

func withOpcode(opcode int) requestOption {
	return func(m *dns.Msg) { m.Opcode = opcode }
}

func withRD(m *dns.Msg) { m.RecursionDesired = true }

func withCD(m *dns.Msg) { m.CheckingDisabled = true }

func withAD(m *dns.Msg) { m.AuthenticatedData = true }

func withAuthority(t *testing.T, record string) requestOption {
	return func(m *dns.Msg) { m.Ns = append(m.Ns, mustRR(t, record)) }
}

func askWith(name string, qtype uint16, opts ...requestOption) *dns.Msg {
	request := ask(name, qtype)
	for _, opt := range opts {
		opt(request)
	}
	return request
}

// rawQuery is a request of a header that announces one question followed by the octets given, which need not make a whole question.
func rawQuery(id uint16, question []byte) []byte {
	packet := make([]byte, headerLength, headerLength+len(question))
	binary.BigEndian.PutUint16(packet[0:], id)
	binary.BigEndian.PutUint16(packet[4:], 1)
	return append(packet, question...)
}

func wireName(t *testing.T, name string) []byte {
	t.Helper()
	buf := make([]byte, maxNameWireLength)
	n, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestAnswers(t *testing.T) {
	xip, address := startExampleServer(t, exampleZoneFile)
	_, longAddress := startExampleServer(t, longZoneFile(t))

	t.Run("questions the zone answers", func(t *testing.T) {
		for _, row := range exampleZoneRows(t) {
			t.Run(row.name, func(t *testing.T) {
				server := address
				if row.longZone {
					server = longAddress
				}
				for _, exchange := range row.exchanges {
					setChallenge(t, xip, exchange.challenge)
					question := exchange.request.Question[0]
					t.Run(fmt.Sprintf("%s %s", question.Name, dns.Type(question.Qtype)), func(t *testing.T) {
						exchangeAndCheck(t, server, exchange.request, exchange.want)
					})
				}
				setChallenge(t, xip, nil)
			})
		}
	})

	refused := answerWant{rcode: dns.RcodeRefused}
	formErr := answerWant{rcode: dns.RcodeFormatError}
	notImp := answerWant{rcode: dns.RcodeNotImplemented}
	t.Run("requests refused, not implemented or malformed", func(t *testing.T) {
		rows := []struct {
			name     string
			requests []*dns.Msg
			want     answerWant
		}{
			{name: "example.test. TXT in class CH", requests: []*dns.Msg{askWith(exampleApex, dns.TypeTXT, inClass(dns.ClassCHAOS))}, want: refused},
			{name: "_acme-challenge.example.test. TXT in class CH", requests: []*dns.Msg{askWith("_acme-challenge.example.test.", dns.TypeTXT, inClass(dns.ClassCHAOS))}, want: refused},
			{name: "10-0-0-1.example.test. A in class ANY", requests: []*dns.Msg{askWith("10-0-0-1.example.test.", dns.TypeA, inClass(dns.ClassANY))}, want: refused},
			{name: "example.test. A in class 0", requests: []*dns.Msg{askWith(exampleApex, dns.TypeA, inClass(0))}, want: formErr},
			{name: "zone transfers", requests: []*dns.Msg{ask(exampleApex, dns.TypeAXFR), ask(exampleApex, dns.TypeIXFR), ask("sub.example.test.", dns.TypeAXFR)}, want: refused},
			{name: "example.test. IXFR with an SOA record in the authority section", requests: []*dns.Msg{askWith(exampleApex, dns.TypeIXFR, withAuthority(t, exampleSOA))}, want: refused},
			{name: "names outside the zone", requests: []*dns.Msg{ask("other.test.", dns.TypeA), ask("test.", dns.TypeNS), ask("xexample.test.", dns.TypeA), ask("example.test.other.test.", dns.TypeA)}, want: refused},
			{name: "NOTIFY inside and outside the zone", requests: []*dns.Msg{askWith(exampleApex, dns.TypeSOA, withOpcode(dns.OpcodeNotify)), askWith("other.test.", dns.TypeSOA, withOpcode(dns.OpcodeNotify))}, want: notImp},
			{name: "NOTIFY in class 0 with RD set is NOTIMP with RD clear", requests: []*dns.Msg{askWith(exampleApex, dns.TypeSOA, withOpcode(dns.OpcodeNotify), inClass(0), withRD)}, want: notImp},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				for _, request := range row.requests {
					exchangeAndCheck(t, address, request, row.want)
				}
			})
		}

		apexName := wireName(t, exampleApex)
		typeA := []byte{0, byte(dns.TypeA)}
		rawRows := []struct {
			name         string
			question     []byte
			wantQuestion []dns.Question
		}{
			{name: "a twelve-octet header that announces one question", question: nil, wantQuestion: []dns.Question{}},
			{name: "a question that ends after its name", question: apexName, wantQuestion: []dns.Question{{Name: exampleApex}}},
			{name: "a question that ends after its type", question: append(slices.Clone(apexName), typeA...), wantQuestion: []dns.Question{{Name: exampleApex, Qtype: dns.TypeA}}},
		}
		for i, row := range rawRows {
			t.Run("raw packet: "+row.name, func(t *testing.T) {
				id := uint16(0x5100 + i)
				reply := exchangeRaw(t, address, rawQuery(id, row.question))
				request := &dns.Msg{MsgHdr: dns.MsgHdr{Id: id, Opcode: dns.OpcodeQuery}}
				resp := checkReply(t, reply, request, formErr, "")
				if got := resp.Question; len(got) != len(row.wantQuestion) || (len(got) > 0 && got[0] != row.wantQuestion[0]) {
					t.Errorf("question section = %v, want %v", got, row.wantQuestion)
				}
			})
		}

		direct := []struct {
			name         string
			questions    []dns.Question
			wantQuestion []dns.Question
		}{
			{
				name:         "two questions",
				questions:    []dns.Question{{Name: exampleApex, Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "www.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
				wantQuestion: []dns.Question{{Name: exampleApex, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
			},
			{name: "no question"},
		}
		for _, row := range direct {
			t.Run("handler called directly with "+row.name, func(t *testing.T) {
				request := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7, Opcode: dns.OpcodeQuery}, Question: row.questions}
				writer := &recordingWriter{}
				xip.handleDnsRequest(writer, request)
				assertOneWrite(t, writer)
				packed, err := writer.written.Pack()
				if err != nil {
					t.Fatal(err)
				}
				resp := checkReply(t, packed, request, formErr, "")
				if !slices.Equal(resp.Question, row.wantQuestion) {
					t.Errorf("question section = %v, want %v", resp.Question, row.wantQuestion)
				}
			})
		}
	})

	t.Run("header flags that do not change the answer", func(t *testing.T) {
		rows := []struct {
			name    string
			request *dns.Msg
			want    answerWant
		}{
			{name: "example.test. SOA with CD and AD set", request: askWith(exampleApex, dns.TypeSOA, withCD, withAD), want: positive("{q} 3600 IN SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 3600")},
			{name: "10-0-0-1.example.test. A with RD set", request: askWith("10-0-0-1.example.test.", dns.TypeA, withRD), want: positive("{q} 86400 IN A 10.0.0.1")},
			{name: "sub.example.test. NS with CD set", request: askWith("sub.example.test.", dns.TypeNS, withCD), want: answerWant{
				rcode:      dns.RcodeSuccess,
				authority:  []string{"sub.example.test. 300 IN NS ns1.sub.example.test.", "sub.example.test. 300 IN NS ns.other.test."},
				additional: []string{"ns1.sub.example.test. 300 IN A 192.0.2.1"},
			}},
			{name: "other.test. A with CD set", request: askWith("other.test.", dns.TypeA, withCD), want: refused},
			{name: "nope.example.test. A with CD set", request: askWith("nope.example.test.", dns.TypeA, withCD), want: noData},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				exchangeAndCheck(t, address, row.request, row.want)
			})
		}
	})
}

func TestAnswersWithoutDelegations(t *testing.T) {
	t.Run("a zone file without a cut is served", func(t *testing.T) {
		_, address := startExampleServer(t, "@ TXT \"only\"\nwww A 192.0.2.80\n")
		exchangeAndCheck(t, address, ask(exampleApex, dns.TypeTXT), positive(`{q} 300 IN TXT "only"`))
		exchangeAndCheck(t, address, ask("www.example.test.", dns.TypeA), positive("{q} 300 IN A 192.0.2.80"))
	})
	t.Run("a server without a zone file has no TXT record at its apex", func(t *testing.T) {
		address := startTestServer(t, WithDomain(exampleDomain), WithEmail(exampleEmail), WithNameServers(exampleNameServers))
		exchangeAndCheck(t, address, ask(exampleApex, dns.TypeTXT), noData)
	})
}

func TestAnswersInTheCaseAsked(t *testing.T) {
	_, address := startExampleServer(t, exampleZoneFile)
	tests := []struct {
		name  string
		qname string
		want  string
	}{
		{name: "a static name", qname: "wWw.ExAmPlE.tEsT.", want: "{q} 300 IN A 192.0.2.80"},
		{name: "a name that carries an address", qname: "App.10-0-0-1.EXAMPLE.test.", want: "{q} 86400 IN A 10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name+" is answered with records owned in the case asked", func(t *testing.T) {
			exchangeAndCheck(t, address, ask(tt.qname, dns.TypeA), positive(tt.want))
		})
	}
}

// capitalise upper-cases the letters of name whose position, counted among the letters, selects a set bit of pattern, so that 32 patterns give 32 spellings of a name with at least five letters.
func capitalise(name string, pattern int) string {
	b := []byte(name)
	letter := 0
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			if pattern>>(letter%5)&1 == 1 {
				b[i] = c - ('a' - 'A')
			}
			letter++
		}
	}
	return string(b)
}

// TestConcurrentAnswersKeepStoredRecords serves the same stored record sets to many questions at once, each spelled differently, so that the race detector sees any write to a stored record and a shared record would show up in another reply's owner names.
func TestConcurrentAnswersKeepStoredRecords(t *testing.T) {
	xip, address := startExampleServer(t, exampleZoneFile)
	before := storedRecords(xip.zone)

	questions := []struct {
		name  string
		qtype uint16
	}{
		{exampleApex, dns.TypeMX},
		{exampleApex, dns.TypeNS},
		{"multi.example.test.", dns.TypeTXT},
		{"alias.example.test.", dns.TypeA},
		{"www.example.test.", dns.TypeAAAA},
	}
	const goroutines = 32
	var wg sync.WaitGroup
	for pattern := range goroutines {
		wg.Go(func() {
			client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
			for _, question := range questions {
				qname := capitalise(question.name, pattern)
				resp, _, err := client.ExchangeContext(t.Context(), ask(qname, question.qtype), address)
				if err != nil {
					t.Errorf("%s: %v", qname, err)
					return
				}
				if len(resp.Answer) == 0 {
					t.Errorf("%s %s: no answer:\n%s", qname, dns.Type(question.qtype), resp)
				}
				for _, rr := range resp.Answer {
					if rr.Header().Name != qname {
						t.Errorf("%s %s: answer %q is not owned by the name as asked", qname, dns.Type(question.qtype), rr)
					}
				}
			}
		})
	}
	wg.Wait()

	if after := storedRecords(xip.zone); !slices.Equal(after, before) {
		t.Errorf("the stored records changed while serving:\nbefore %q\nafter  %q", before, after)
	}
}

// challengeAnswerSizeOf packs the TXT answer at the challenge name of example.test independently of AddChallenge: the name in upper case as the question, one record per value, each cut into strings of 255 octets.
func challengeAnswerSizeOf(t *testing.T, values []string) int {
	t.Helper()
	qname := strings.ToUpper(challengeLabel + exampleApex)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeTXT)
	msg.Compress = true
	for _, value := range values {
		var txt []string
		for len(value) > 255 {
			txt, value = append(txt, value[:255]), value[255:]
		}
		msg.Answer = append(msg.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: append(txt, value)})
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return len(packed)
}

// challengeValue is a value of the length the certificate manager publishes, 43 octets.
func challengeValue(i int) string {
	return fmt.Sprintf("value-%037d", i)
}

func TestAddChallengeBound(t *testing.T) {
	xip, address := startExampleServer(t, exampleZoneFile)
	name := challengeLabel + exampleApex
	published := challengeValue(0)
	if err := xip.AddChallenge(name, published); err != nil {
		t.Fatal(err)
	}

	oversized := strings.Repeat("o", 65200)
	size := challengeAnswerSizeOf(t, []string{published, oversized})
	if size <= maxReplyWithoutOPT {
		t.Fatalf("the values make an answer of %d octets, which fits in a DNS message with an OPT record: choose a longer value", size)
	}
	t.Run("a value that would make the answer too large for a DNS message is refused with its size", func(t *testing.T) {
		err := xip.AddChallenge(name, oversized)
		want := fmt.Sprintf("xip: publishing this value at %s would make the TXT answer %d octets, more than the limit of 65524 octets for a DNS message", name, size)
		if err == nil || err.Error() != want {
			t.Errorf("AddChallenge error = %v, want %q", err, want)
		}
	})

	wantAnswer := fmt.Sprintf("{q} 0 IN TXT %q", published)
	t.Run("the published set is unchanged", func(t *testing.T) {
		exchangeAndCheck(t, address, ask(name, dns.TypeTXT), positive(wantAnswer))
	})

	t.Run("a value already published is accepted again", func(t *testing.T) {
		if err := xip.AddChallenge(name, published); err != nil {
			t.Errorf("AddChallenge of a published value: %v", err)
		}
		exchangeAndCheck(t, address, ask(name, dns.TypeTXT), positive(wantAnswer))
	})
}

func TestAddChallengeBoundConcurrent(t *testing.T) {
	xip, address := startExampleServer(t, exampleZoneFile)
	name := challengeLabel + exampleApex
	const goroutines = 16
	// Every value has the same length, so any set of n values makes an answer of the same size; at this length a handful fit in a DNS message.
	value := func(i int) string {
		return fmt.Sprintf("value-%02d-", i) + strings.Repeat("v", 9991)
	}
	firstValues := func(n int) []string {
		values := make([]string, n)
		for i := range values {
			values[i] = value(i)
		}
		return values
	}
	fitting := 0
	for fitting < goroutines && challengeAnswerSizeOf(t, firstValues(fitting+1)) <= maxReplyWithoutOPT {
		fitting++
	}
	if fitting == goroutines {
		t.Fatalf("all %d values fit, so the calls never compete for the limit", goroutines)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0
	for i := range goroutines {
		wg.Go(func() {
			if err := xip.AddChallenge(name, value(i)); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	request := ask(strings.ToUpper(name), dns.TypeTXT)
	request.SetEdns0(1232, false)
	resp := exchangeOver(t, "tcp", address, request)
	if resp.Truncated {
		t.Error("the TXT answer is truncated over TCP")
	}
	if len(resp.Answer) != succeeded {
		t.Errorf("%d values are served, but %d calls succeeded", len(resp.Answer), succeeded)
	}
	if succeeded != fitting {
		t.Errorf("%d calls succeeded, want %d: as many as fit", succeeded, fitting)
	}
}
