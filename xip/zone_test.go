package xip

import (
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// exampleZoneFile is the zone file of the examples of B8.
// The record with its own TTL comes last because, without a $TTL directive, a TTL written on a record becomes the default of every record after it (RFC 1035 section 5.1).
const exampleZoneFile = `@               TXT    "v=spf1 -all"
@               MX     10 mail.other.test.
@               MX     20 www
@               AAAA   2001:db8::1
@               CAA    0 issue "letsencrypt.org"
www             A      192.0.2.80
www             AAAA   2001:db8::80
alias           CNAME  target.other.test.
_sip._tcp       SRV    0 5 5060 sip.other.test.
deep.er.name    TXT    "deep"
multi           TXT    "one" "two"
UPPER           TXT    "upper"
esc\065ped      TXT    "escaped"
parent          TXT    "above a cut"
child.parent    NS     ns.other.test.
cparent         CNAME  target.other.test.
child.cparent   NS     ns.other.test.
sub             NS     ns1.sub
sub             NS     ns.other.test.
ns1.sub         A      192.0.2.1
addr            NS     10-0-0-53.addr
10-0-0-53.addr  A      192.0.2.53
octets          CAA    0 issue "a\\097\098"
octets          TXT    "a\\097\098"
short        60 TXT    "short-lived"
`

const (
	exampleDomain = "example.test"
	exampleApex   = "example.test."
	exampleEmail  = "admin@example.test"
	exampleSOA    = "example.test. 300 IN SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"
)

var exampleNameServers = []string{"192.0.2.10", "192.0.2.11"}

func exampleAddresses() []netip.Addr {
	addresses := make([]netip.Addr, len(exampleNameServers))
	for i, ns := range exampleNameServers {
		addresses[i] = netip.MustParseAddr(ns)
	}
	return addresses
}

// newExampleZone builds the zone of B8 for domain example.test from a zone file, without NewXip and without a socket.
func newExampleZone(t *testing.T, zoneFileContent string) *zone {
	t.Helper()
	file, err := parseZoneFile(strings.NewReader(zoneFileContent), testZoneFileName, zoneServer{
		origin:        exampleDomain,
		nameServers:   nameServerNames(exampleApex, len(exampleNameServers)),
		challengeName: challengeLabel + exampleApex,
		addresses:     exampleAddresses(),
	})
	if err != nil {
		t.Fatalf("parseZoneFile: %v", err)
	}
	z, err := newZone(exampleDomain, exampleEmail, exampleAddresses(), file)
	if err != nil {
		t.Fatalf("newZone: %v", err)
	}
	return z
}

// nameOfWireLength puts labels of x in front of suffix until the name is exactly octets long in wire format.
func nameOfWireLength(t testing.TB, octets int, suffix string) string {
	t.Helper()
	var b strings.Builder
	remaining := octets - wireLengthOf(t, suffix)
	for remaining > 0 {
		length := min(maxLabelLength, remaining-1)
		if remaining-(length+1) == 1 {
			length--
		}
		if length < 1 {
			t.Fatalf("no name of %d octets ends with %s", octets, suffix)
		}
		b.WriteString(strings.Repeat("x", length))
		b.WriteByte('.')
		remaining -= length + 1
	}
	name := b.String() + suffix
	if got := wireLengthOf(t, name); got != octets {
		t.Fatalf("built a name of %d octets, want %d: %s", got, octets, name)
	}
	return name
}

func wireLengthOf(t testing.TB, name string) int {
	t.Helper()
	buf := make([]byte, 2*maxNameWireLength)
	length, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("packing %s: %v", name, err)
	}
	return length
}

// answerWant is what a reply must hold. In the record texts, {q} stands for the question name as asked.
type answerWant struct {
	rcode                         int
	aa                            bool
	answer, authority, additional []string
	// answerOctets replaces answer for values the library prints and reads back unfaithfully, such as a CAA value that holds a backslash: the answer records are compared as they are on the wire.
	answerOctets []wireRecord
}

// wireRecord is a resource record as its octets read on the wire, its owner decoded; an owner of {q} stands for the question name as asked.
type wireRecord struct {
	owner  string
	rrtype uint16
	class  uint16
	ttl    uint32
	rdata  string
}

// answerRecordsOf reads the answer section of a packed message octet by octet, so that no value goes through the library's presentation form.
func answerRecordsOf(t *testing.T, msg []byte) []wireRecord {
	t.Helper()
	if len(msg) < 12 {
		t.Fatalf("a message of %d octets has no header", len(msg))
	}
	questions, answers := binary.BigEndian.Uint16(msg[4:]), binary.BigEndian.Uint16(msg[6:])
	off := 12
	var err error
	for range questions {
		if _, off, err = dns.UnpackDomainName(msg, off); err != nil {
			t.Fatalf("reading a question name: %v", err)
		}
		off += 4
	}
	records := make([]wireRecord, answers)
	for i := range records {
		if records[i].owner, off, err = dns.UnpackDomainName(msg, off); err != nil {
			t.Fatalf("reading the owner of answer %d: %v", i, err)
		}
		if off+10 > len(msg) {
			t.Fatalf("answer %d is cut short in its header", i)
		}
		records[i].rrtype = binary.BigEndian.Uint16(msg[off:])
		records[i].class = binary.BigEndian.Uint16(msg[off+2:])
		records[i].ttl = binary.BigEndian.Uint32(msg[off+4:])
		length := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+length > len(msg) {
			t.Fatalf("answer %d is cut short in its data", i)
		}
		records[i].rdata = string(msg[off : off+length])
		off += length
	}
	return records
}

// checkAnswerOctets compares the answer section of a packed message with the records a row wants, octet for octet.
func checkAnswerOctets(t *testing.T, label string, msg []byte, want []wireRecord, qname string) {
	t.Helper()
	expanded := make([]wireRecord, len(want))
	for i, record := range want {
		expanded[i] = record
		expanded[i].owner = strings.ReplaceAll(record.owner, "{q}", qname)
	}
	if got := answerRecordsOf(t, msg); !slices.Equal(got, expanded) {
		t.Errorf("%s: answer on the wire = %#v, want %#v", label, got, expanded)
	}
}

type answerExchange struct {
	request *dns.Msg
	want    answerWant
	// challenge holds the values published at the challenge name when the request is sent, in the order they are published.
	challenge []string
}

// answerRow is one line of the tables of B8.
type answerRow struct {
	name      string
	exchanges []answerExchange
	// lookup marks the rows that reach zone.lookup: not the referrals, the DS at a cut, the challenge name or the refusals.
	lookup bool
	// longZone selects the zone whose file declares a record at a name of 255 octets.
	longZone bool
}

func ask(name string, qtype uint16) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion(name, qtype)
	request.RecursionDesired = false
	return request
}

func asks(names []string, qtypes ...uint16) []*dns.Msg {
	var requests []*dns.Msg
	for _, name := range names {
		for _, qtype := range qtypes {
			requests = append(requests, ask(name, qtype))
		}
	}
	return requests
}

func exchanges(want answerWant, requests ...*dns.Msg) []answerExchange {
	result := make([]answerExchange, len(requests))
	for i, request := range requests {
		result[i] = answerExchange{request: request, want: want}
	}
	return result
}

// publishing sets the values published at the challenge name for each exchange.
func publishing(values []string, exchanges []answerExchange) []answerExchange {
	for i := range exchanges {
		exchanges[i].challenge = values
	}
	return exchanges
}

func positive(records ...string) answerWant {
	return answerWant{rcode: dns.RcodeSuccess, aa: true, answer: records}
}

var (
	noData   = answerWant{rcode: dns.RcodeSuccess, aa: true, authority: []string{exampleSOA}}
	noName   = answerWant{rcode: dns.RcodeNameError, aa: true, authority: []string{exampleSOA}}
	hinfo    = positive(`{q} 3600 IN HINFO "RFC8482" ""`)
	aliasFor = positive("{q} 300 IN CNAME target.other.test.")
)

// exampleZoneRows are the lines of B8.1, the questions the zone answers.
func exampleZoneRows(t *testing.T) []answerRow {
	t.Helper()
	name253 := nameOfWireLength(t, 253, exampleApex)
	name254 := nameOfWireLength(t, 254, exampleApex)
	name255 := nameOfWireLength(t, 255, exampleApex)
	address255 := nameOfWireLength(t, 255, "10-0-0-1."+exampleApex)
	const newFormLabel = "app-10-0-0-1."
	newForm254 := newFormLabel + nameOfWireLength(t, 254-len(newFormLabel), exampleApex)
	newForm255 := newFormLabel + nameOfWireLength(t, 255-len(newFormLabel), exampleApex)
	if wireLengthOf(t, newForm254) != 254 || wireLengthOf(t, newForm255) != 255 {
		t.Fatalf("built names of %d and %d octets, want 254 and 255", wireLengthOf(t, newForm254), wireLengthOf(t, newForm255))
	}
	subReferral := answerWant{
		rcode:      dns.RcodeSuccess,
		authority:  []string{"sub.example.test. 300 IN NS ns1.sub.example.test.", "sub.example.test. 300 IN NS ns.other.test."},
		additional: []string{"ns1.sub.example.test. 300 IN A 192.0.2.1"},
	}
	challengeNoData := answerWant{rcode: dns.RcodeSuccess, aa: true, authority: []string{"example.test. 0 IN SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"}}
	look := func(name string, want answerWant, requests ...*dns.Msg) answerRow {
		return answerRow{name: name, exchanges: exchanges(want, requests...), lookup: true}
	}

	return []answerRow{
		look("example.test. SOA", positive("{q} 300 IN SOA ns1.example.test. admin.example.test. 2024072600 900 900 1800 300"), ask(exampleApex, dns.TypeSOA)),
		look("example.test. NS", answerWant{
			rcode: dns.RcodeSuccess, aa: true,
			answer:     []string{"{q} 300 IN NS ns1.example.test.", "{q} 300 IN NS ns2.example.test."},
			additional: []string{"ns1.example.test. 300 IN A 192.0.2.10", "ns2.example.test. 300 IN A 192.0.2.11"},
		}, ask(exampleApex, dns.TypeNS)),
		look("example.test. A", positive("{q} 300 IN A 192.0.2.10", "{q} 300 IN A 192.0.2.11"), ask(exampleApex, dns.TypeA)),
		look("example.test. TXT", positive(`{q} 300 IN TXT "v=spf1 -all"`), ask(exampleApex, dns.TypeTXT)),
		look("example.test. MX", positive("{q} 300 IN MX 10 mail.other.test.", "{q} 300 IN MX 20 www.example.test."), ask(exampleApex, dns.TypeMX)),
		look("example.test. AAAA", positive("{q} 300 IN AAAA 2001:db8::1"), ask(exampleApex, dns.TypeAAAA)),
		look("example.test. CAA", positive(`{q} 300 IN CAA 0 issue "letsencrypt.org"`), ask(exampleApex, dns.TypeCAA)),
		look("example.test. DS, DNSKEY, SRV, HTTPS, TYPE65280, OPT, TSIG and TKEY have no data", noData,
			asks([]string{exampleApex}, dns.TypeDS, dns.TypeDNSKEY, dns.TypeSRV, dns.TypeHTTPS, 65280, dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY)...),
		look("example.test. ANY is the HINFO record", hinfo, ask(exampleApex, dns.TypeANY)),
		look("www.example.test. ANY, a name with records from the zone file, is the HINFO record", hinfo, ask("www.example.test.", dns.TypeANY)),
		look("ns1.example.test. ANY, a name with a built-in record, is the HINFO record", hinfo, ask("ns1.example.test.", dns.TypeANY)),
		look("EXAMPLE.Test. TXT is owned by the name as asked", positive(`EXAMPLE.Test. 300 IN TXT "v=spf1 -all"`), ask("EXAMPLE.Test.", dns.TypeTXT)),
		look("ns1.example.test. A", positive("{q} 300 IN A 192.0.2.10"), ask("ns1.example.test.", dns.TypeA)),
		look("ns1.example.test. AAAA has no data", noData, ask("ns1.example.test.", dns.TypeAAAA)),
		look("www.example.test. A", positive("{q} 300 IN A 192.0.2.80"), ask("www.example.test.", dns.TypeA)),
		look("www.example.test. TXT has no data", noData, ask("www.example.test.", dns.TypeTXT)),
		look("alias.example.test. of every type is the CNAME alone", aliasFor,
			asks([]string{"alias.example.test."}, dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeNS, dns.TypeSOA, dns.TypeDS, dns.TypeOPT, dns.TypeCNAME, dns.TypeANY)...),
		look("_sip._tcp.example.test. SRV", positive("{q} 300 IN SRV 0 5 5060 sip.other.test."), ask("_sip._tcp.example.test.", dns.TypeSRV)),
		look("multi.example.test. TXT is one record with two strings", positive(`{q} 300 IN TXT "one" "two"`), ask("multi.example.test.", dns.TypeTXT)),
		look("octets.example.test. CAA keeps a literal backslash and an escaped octet of its value", answerWant{
			rcode: dns.RcodeSuccess, aa: true,
			answerOctets: []wireRecord{{owner: "{q}", rrtype: dns.TypeCAA, class: dns.ClassINET, ttl: 300, rdata: "\x00\x05issue" + `a\097b`}},
		}, ask("octets.example.test.", dns.TypeCAA)),
		look("octets.example.test. TXT keeps a literal backslash and an escaped octet of its string", answerWant{
			rcode: dns.RcodeSuccess, aa: true,
			answerOctets: []wireRecord{{owner: "{q}", rrtype: dns.TypeTXT, class: dns.ClassINET, ttl: 300, rdata: "\x06" + `a\097b`}},
		}, ask("octets.example.test.", dns.TypeTXT)),
		look("short.example.test. TXT keeps the TTL the zone file gives it", positive(`{q} 60 IN TXT "short-lived"`), ask("short.example.test.", dns.TypeTXT)),
		look("upper.example.test. TXT in either case", positive(`{q} 300 IN TXT "upper"`), asks([]string{"upper.example.test.", "UPPER.example.test."}, dns.TypeTXT)...),
		look("escaped.example.test. TXT", positive(`{q} 300 IN TXT "escaped"`), ask("escaped.example.test.", dns.TypeTXT)),
		look("parent.example.test. TXT above a cut", positive(`{q} 300 IN TXT "above a cut"`), ask("parent.example.test.", dns.TypeTXT)),
		look("cparent.example.test. A and CNAME above a cut", aliasFor, asks([]string{"cparent.example.test."}, dns.TypeA, dns.TypeCNAME)...),
		look(`a\.b.example.test. A, whose first label holds a dot, has no data`, noData, ask(`a\.b.example.test.`, dns.TypeA)),
		look(`1\.2\.3\.4.example.test. A, one label that holds an address, has no data`, noData, ask(`1\.2\.3\.4.example.test.`, dns.TypeA)),
		look("empty non-terminals have no data", noData,
			ask("_tcp.example.test.", dns.TypeA), ask("er.name.example.test.", dns.TypeTXT), ask("name.example.test.", dns.TypeANY)),
		look("names that carry an address have its A record", positive("{q} 300 IN A 10.0.0.1"),
			asks([]string{"10-0-0-1.example.test.", "app.10.0.0.1.example.test.", "10.0.0.1.app.example.test."}, dns.TypeA)...),
		look("a name that carries an address has no data of other types", noData,
			asks([]string{"10-0-0-1.example.test."}, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeNS, dns.TypeSOA, dns.TypeCNAME, dns.TypeCAA, dns.TypeDS, dns.TypeHTTPS)...),
		look("10-0-0-1.example.test. ANY is the HINFO record", hinfo, ask("10-0-0-1.example.test.", dns.TypeANY)),
		look("aPp-10-0-0-1.Example.TEST. A, an address after a name in its label, is owned by the name as asked", positive("{q} 300 IN A 10.0.0.1"), ask("aPp-10-0-0-1.Example.TEST.", dns.TypeA)),
		look("app-10-0-0-1.example.test. AAAA has no data", noData, ask("app-10-0-0-1.example.test.", dns.TypeAAAA)),
		look("app-10-0-0-1.example.test. ANY is the HINFO record", hinfo, ask("app-10-0-0-1.example.test.", dns.TypeANY)),
		look("parents of a dotted name have no data", noData,
			ask("1.example.test.", dns.TypeA), ask("0.1.example.test.", dns.TypeA), ask("0.0.1.example.test.", dns.TypeNS)),
		look("nope.example.test. has no data", noData, asks([]string{"nope.example.test."}, dns.TypeA, dns.TypeTXT, dns.TypeNS, dns.TypeANY)...),
		look("a name of 253 octets that owns nothing has no data", noData, asks([]string{name253}, dns.TypeA, dns.TypeNS)...),
		look("names of 254 and 255 octets that own nothing do not exist", noName, asks([]string{name254, name255}, dns.TypeA, dns.TypeTXT, dns.TypeANY)...),
		look("a name of 255 octets that carries an address has its A record", positive("{q} 300 IN A 10.0.0.1"), ask(address255, dns.TypeA)),
		look("a name of 255 octets that carries an address has no AAAA record", noData, ask(address255, dns.TypeAAAA)),
		look("names of 254 and 255 octets whose first label carries an address after a name have its A record", positive("{q} 300 IN A 10.0.0.1"), asks([]string{newForm254, newForm255}, dns.TypeA)...),
		look("names of 254 and 255 octets whose first label carries an address after a name have no AAAA record", noData, asks([]string{newForm254, newForm255}, dns.TypeAAAA)...),
		look("names of 254 and 255 octets whose first label carries an address after a name have the HINFO record for ANY", hinfo, asks([]string{newForm254, newForm255}, dns.TypeANY)...),
		{name: "a name of 255 octets that owns a TXT record has it", exchanges: exchanges(positive(`{q} 300 IN TXT "long"`), ask(name255, dns.TypeTXT)), lookup: true, longZone: true},
		{name: "a name of 255 octets that owns a TXT record has no A record", exchanges: exchanges(noData, ask(name255, dns.TypeA)), lookup: true, longZone: true},
		{name: "names at and below the cut sub are referred", exchanges: exchanges(subReferral,
			ask("sub.example.test.", dns.TypeNS), ask("x.sub.example.test.", dns.TypeA), ask("sub.example.test.", dns.TypeANY), ask("x.sub.example.test.", dns.TypeDS))},
		{name: "sub.example.test. DS is this zone's NODATA", exchanges: exchanges(noData, ask("sub.example.test.", dns.TypeDS))},
		{name: "cuts below names with records are referred", exchanges: append(
			exchanges(answerWant{rcode: dns.RcodeSuccess, authority: []string{"child.parent.example.test. 300 IN NS ns.other.test."}}, ask("child.parent.example.test.", dns.TypeA)),
			exchanges(answerWant{rcode: dns.RcodeSuccess, authority: []string{"child.cparent.example.test. 300 IN NS ns.other.test."}}, ask("child.cparent.example.test.", dns.TypeA))...)},
		{name: "a cut whose name server carries an address is referred with its glue", exchanges: exchanges(answerWant{
			rcode:      dns.RcodeSuccess,
			authority:  []string{"addr.example.test. 300 IN NS 10-0-0-53.addr.example.test."},
			additional: []string{"10-0-0-53.addr.example.test. 300 IN A 192.0.2.53"},
		}, ask("10-0-0-53.addr.example.test.", dns.TypeA))},
		{name: "_acme-challenge TXT without a value has no data with TTL 0", exchanges: exchanges(challengeNoData, ask("_acme-challenge.example.test.", dns.TypeTXT))},
		{name: "_acme-challenge TXT has the values in sorted order with TTL 0", exchanges: publishing([]string{"b", "a"},
			exchanges(positive(`{q} 0 IN TXT "a"`, `{q} 0 IN TXT "b"`), ask("_acme-challenge.example.test.", dns.TypeTXT)))},
		{name: "_acme-challenge ANY with a value is the HINFO record with TTL 0", exchanges: publishing([]string{"a"},
			exchanges(positive(`{q} 0 IN HINFO "RFC8482" ""`), ask("_acme-challenge.example.test.", dns.TypeANY)))},
		{name: "_acme-challenge ANY without a value and A at any time have no data with TTL 0", exchanges: append(
			exchanges(challengeNoData, ask("_acme-challenge.example.test.", dns.TypeANY), ask("_acme-challenge.example.test.", dns.TypeA)),
			publishing([]string{"a"}, exchanges(challengeNoData, ask("_acme-challenge.example.test.", dns.TypeA)))...)},
	}
}

// longZoneFile declares a TXT record at a name of 255 octets, the longest a name can be.
func longZoneFile(t *testing.T) string {
	return nameOfWireLength(t, 255, exampleApex) + ` TXT "long"` + "\n"
}

// expandRecords parses the record texts of a want, with {q} replaced by the question name, into the form stringsOf gives.
func expandRecords(t *testing.T, texts []string, qname string) []string {
	t.Helper()
	records := make([]string, len(texts))
	for i, text := range texts {
		records[i] = rrString(t, strings.ReplaceAll(text, "{q}", qname))
	}
	return records
}

func TestLookup(t *testing.T) {
	zones := map[bool]*zone{
		false: newExampleZone(t, exampleZoneFile),
		true:  newExampleZone(t, longZoneFile(t)),
	}
	for _, row := range exampleZoneRows(t) {
		if !row.lookup {
			continue
		}
		t.Run(row.name, func(t *testing.T) {
			z := zones[row.longZone]
			for _, exchange := range row.exchanges {
				question := exchange.request.Question[0]
				label := fmt.Sprintf("%s %s", question.Name, dns.Type(question.Qtype))
				wantKind := lookupNoData
				switch {
				case exchange.want.rcode == dns.RcodeNameError:
					wantKind = lookupNoName
				case len(exchange.want.answer) > 0, len(exchange.want.answerOctets) > 0:
					wantKind = lookupAnswer
				}

				kind, answer, additional := z.lookup(question, dns.CanonicalName(question.Name))
				if kind != wantKind {
					t.Errorf("%s: kind = %d, want %d", label, kind, wantKind)
				}
				if exchange.want.answerOctets != nil {
					msg := new(dns.Msg)
					msg.SetQuestion(question.Name, question.Qtype)
					msg.Answer = answer
					packed, err := msg.Pack()
					if err != nil {
						t.Fatalf("%s: packing the answer: %v", label, err)
					}
					checkAnswerOctets(t, label, packed, exchange.want.answerOctets, question.Name)
				} else if got, want := stringsOf(answer), expandRecords(t, exchange.want.answer, question.Name); !slices.Equal(got, want) {
					t.Errorf("%s: answer = %q, want %q", label, got, want)
				}
				if got, want := stringsOf(additional), expandRecords(t, exchange.want.additional, question.Name); !slices.Equal(got, want) {
					t.Errorf("%s: additional = %q, want %q", label, got, want)
				}
			}
		})
	}
}

func TestLookupExistenceAtTheLengthLimit(t *testing.T) {
	z := newExampleZone(t, longZoneFile(t))
	tests := []struct {
		name   string
		qname  string
		qtype  uint16
		want   lookupKind
		answer []string
	}{
		{name: "a name of 253 octets that owns nothing exists", qname: nameOfWireLength(t, 253, exampleApex), qtype: dns.TypeA, want: lookupNoData},
		{name: "a name of 254 octets that owns nothing does not exist", qname: nameOfWireLength(t, 254, exampleApex), qtype: dns.TypeA, want: lookupNoName},
		{name: "a name of 255 octets that owns nothing does not exist", qname: nameOfWireLength(t, 255, "nothing."+exampleApex), qtype: dns.TypeAAAA, want: lookupNoName},
		{name: "a name of 253 octets with an escaped dot in a label exists", qname: nameOfWireLength(t, 253, `a\.b.`+exampleApex), qtype: dns.TypeA, want: lookupNoData},
		{name: "a name of 254 octets with an escaped dot in a label does not exist", qname: nameOfWireLength(t, 254, `a\.b.`+exampleApex), qtype: dns.TypeA, want: lookupNoName},
		{name: "a name of 255 octets with an escaped dot in a label does not exist", qname: nameOfWireLength(t, 255, `a\.b.`+exampleApex), qtype: dns.TypeA, want: lookupNoName},
		{name: "a name of 253 octets with a decimal escape exists", qname: nameOfWireLength(t, 253, `\200\201\202.`+exampleApex), qtype: dns.TypeA, want: lookupNoData},
		{name: "a name of 254 octets with a decimal escape does not exist", qname: nameOfWireLength(t, 254, `\200\201\202.`+exampleApex), qtype: dns.TypeA, want: lookupNoName},
		{name: "a name of 255 octets that carries an address exists", qname: nameOfWireLength(t, 255, "10-0-0-1."+exampleApex), qtype: dns.TypeA, want: lookupAnswer, answer: []string{"{q} 300 IN A 10.0.0.1"}},
		{name: "a name of 255 octets that owns a zone file record exists", qname: nameOfWireLength(t, 255, exampleApex), qtype: dns.TypeTXT, want: lookupAnswer, answer: []string{`{q} 300 IN TXT "long"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if strings.Contains(tt.qname, `\`) && len(tt.qname) <= maxParentPresentationLength {
				t.Fatalf("the escaped name %s is short enough in presentation form to skip the exact computation it is meant to exercise", tt.qname)
			}
			kind, answer, _ := z.lookup(dns.Question{Name: tt.qname, Qtype: tt.qtype, Qclass: dns.ClassINET}, dns.CanonicalName(tt.qname))
			if kind != tt.want {
				t.Errorf("kind = %d, want %d", kind, tt.want)
			}
			if got, want := stringsOf(answer), expandRecords(t, tt.answer, tt.qname); !slices.Equal(got, want) {
				t.Errorf("answer = %q, want %q", got, want)
			}
		})
	}
}

func TestSOARecordFields(t *testing.T) {
	z, err := newZone("example.test", "Admin.Team@EXAMPLE.Test", []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	soa := z.soa
	fields := []struct {
		name      string
		got, want any
	}{
		{"owner", soa.Hdr.Name, "example.test."},
		{"class", soa.Hdr.Class, uint16(dns.ClassINET)},
		{"TTL", soa.Hdr.Ttl, uint32(300)},
		{"MNAME", soa.Ns, "ns1.example.test."},
		{"RNAME, lower-cased with the dot of the local part escaped", soa.Mbox, `admin\.team.example.test.`},
		{"serial", soa.Serial, uint32(2024072600)},
		{"refresh", soa.Refresh, uint32(900)},
		{"retry", soa.Retry, uint32(900)},
		{"expire", soa.Expire, uint32(1800)},
		{"minimum", soa.Minttl, uint32(300)},
		{"TTL of a negative answer", z.negativeTTL(), uint32(300)},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			if field.got != field.want {
				t.Errorf("%s = %v, want %v", field.name, field.got, field.want)
			}
		})
	}
}

// nameServerAnswerSizeOf packs the NS answer at apex independently of newZone: the apex in upper case as the question, n NS records and their addresses.
func nameServerAnswerSizeOf(t *testing.T, apex string, n int) int {
	t.Helper()
	qname := strings.ToUpper(apex)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeNS)
	msg.Compress = true
	addresses := addressesUpTo(n)
	for i := range n {
		msg.Answer = append(msg.Answer, mustRR(t, fmt.Sprintf("%s 300 IN NS ns%d.%s", qname, i+1, apex)))
		msg.Extra = append(msg.Extra, mustRR(t, fmt.Sprintf("ns%d.%s 300 IN A %s", i+1, apex, addresses[i])))
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("packing the NS answer: %v", err)
	}
	return len(packed)
}

// addressesUpTo returns n different name server addresses.
func addressesUpTo(n int) []netip.Addr {
	addresses := make([]netip.Addr, n)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{10, 0, byte((i + 1) >> 8), byte(i + 1)})
	}
	return addresses
}

// oversizedNameServerList is a number of name servers whose NS answer at example.test does not fit in a DNS message.
const oversizedNameServerList = 2000

func TestNewZoneRefusals(t *testing.T) {
	one := addressesUpTo(1)

	t.Run("a zone without a name server is refused", func(t *testing.T) {
		_, err := newZone(exampleDomain, exampleEmail, nil, nil)
		if want := "xip: at least one name server is required"; err == nil || err.Error() != want {
			t.Errorf("newZone error = %v, want %q", err, want)
		}
	})

	t.Run("a local part of 64 octets cannot be the RNAME", func(t *testing.T) {
		email := strings.Repeat("a", 64) + "@example.test"
		_, err := newZone(exampleDomain, email, one, nil)
		want := "xip: email " + email + " cannot be the RNAME of the SOA record: "
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("newZone error = %v, want one starting with %q", err, want)
		}
	})

	t.Run("an RNAME of 257 octets whose labels each fit is refused", func(t *testing.T) {
		domain := strings.Repeat("1", 63) + "." + strings.Repeat("2", 63) + "." + strings.Repeat("3", 63)
		email := strings.Repeat("a", 63) + "@" + domain
		if octets := 1 + 63 + wireLengthOf(t, domain+"."); octets != 257 {
			t.Fatalf("the RNAME would be %d octets, want 257", octets)
		}
		_, err := newZone(domain, email, one, nil)
		want := "xip: email " + email + " cannot be the RNAME of the SOA record: "
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("newZone error = %v, want one starting with %q", err, want)
		}
	})

	t.Run("name servers whose NS answer does not fit in a DNS message are refused", func(t *testing.T) {
		size := nameServerAnswerSizeOf(t, exampleApex, oversizedNameServerList)
		if size <= maxReplyWithoutOPT {
			t.Fatalf("%d name servers make an NS answer of %d octets, which fits: choose more", oversizedNameServerList, size)
		}
		_, err := newZone(exampleDomain, exampleEmail, addressesUpTo(oversizedNameServerList), nil)
		want := fmt.Sprintf("xip: the answer for example.test. NS takes %d octets, more than the limit of 65524 octets for a DNS message; there are too many name servers for this domain", size)
		if err == nil || err.Error() != want {
			t.Errorf("newZone error = %v, want %q", err, want)
		}
	})
}

// TestNewXipStopsOnTheRefusalsOfB7 shows that a configuration newZone refuses stops NewXip, for every refusal that options NewXip accepts can reach.
func TestNewXipStopsOnTheRefusalsOfB7(t *testing.T) {
	longLocalPart := strings.Repeat("a", 64) + "@example.test"
	_, rnameErr := canonicalName(emailToRname(longLocalPart))
	if rnameErr == nil {
		t.Fatal("a local part of 64 octets makes a valid RNAME: choose another email address")
	}
	tooManyNameServers := make([]string, oversizedNameServerList)
	for i, addr := range addressesUpTo(oversizedNameServerList) {
		tooManyNameServers[i] = addr.String()
	}

	tests := []struct {
		name        string
		domain      string
		email       string
		nameServers []string
		want        string
	}{
		{
			name:        "an email address whose RNAME is not a DNS name",
			domain:      exampleDomain,
			email:       longLocalPart,
			nameServers: exampleNameServers,
			want:        fmt.Sprintf("xip: email %s cannot be the RNAME of the SOA record: %v", longLocalPart, rnameErr),
		},
		{
			name:        "name servers whose NS answer is over the limit",
			domain:      exampleDomain,
			email:       exampleEmail,
			nameServers: tooManyNameServers,
			want:        fmt.Sprintf("xip: the answer for example.test. NS takes %d octets, more than the limit of 65524 octets for a DNS message; there are too many name servers for this domain", nameServerAnswerSizeOf(t, exampleApex, oversizedNameServerList)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+" stops NewXip", func(t *testing.T) {
			xip, err := NewXip(WithDomain(tt.domain), WithEmail(tt.email), WithNameServers(tt.nameServers))
			if err == nil || err.Error() != tt.want {
				t.Errorf("NewXip error = %v, want %q", err, tt.want)
			}
			if xip != nil {
				t.Error("NewXip returned a server together with an error")
			}
		})
	}
}

func TestNegativeTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     uint32
		minimum uint32
		want    uint32
	}{
		{name: "a MINIMUM field below the SOA record's TTL decides", ttl: 300, minimum: 60, want: 60},
		{name: "a TTL below the SOA record's MINIMUM field decides", ttl: 30, minimum: 300, want: 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := &zone{soa: &dns.SOA{Hdr: header(exampleApex, dns.TypeSOA, tt.ttl), Minttl: tt.minimum}}
			if got := z.negativeTTL(); got != tt.want {
				t.Errorf("negativeTTL() = %d, want %d", got, tt.want)
			}
		})
	}
}

// storedRecords lists every record of the zone as text, in a stable order, so that a test can show that serving left them unchanged.
func storedRecords(z *zone) []string {
	var records []string
	for _, owner := range slices.Sorted(maps.Keys(z.records)) {
		for _, rrtype := range slices.Sorted(maps.Keys(z.records[owner])) {
			records = append(records, stringsOf(z.records[owner][rrtype])...)
		}
	}
	for _, cut := range z.cuts.sortedCuts() {
		records = append(records, stringsOf(z.cuts.cuts[cut].nameServers)...)
		records = append(records, stringsOf(z.cuts.cuts[cut].glue)...)
	}
	return records
}
