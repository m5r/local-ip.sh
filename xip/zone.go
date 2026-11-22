package xip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// addressTTL is the TTL of the address a name carries: the answer follows from the name alone, and only a delegation added later at or above the name can change it.
const addressTTL uint32 = 86400

// recordTTL is the TTL of every record the server builds from its configuration, and the SOA's MINIMUM field, so that a negative answer is kept as long: the operator changes the configuration and the zone file rarely and by hand, and publishes a new record that long before anything depends on it.
const recordTTL uint32 = 3600

// anyTTL is the TTL of the HINFO record that answers a query for ANY: RFC 8482 section 4.2 asks for one long enough to suppress frequent repeats.
const anyTTL uint32 = 3600

// maxParentWireLength is the longest name in wire format that can have a name below it: a child adds at least two octets, and a name has at most 255.
const maxParentWireLength = maxNameWireLength - 2

// maxParentPresentationLength bounds the names whose existence needs no exact computation: a presentation form of this many characters, trailing dot included, is at most maxParentWireLength octets long whatever escapes it holds.
const maxParentPresentationLength = maxParentWireLength - 1

type lookupKind int

const (
	lookupAnswer lookupKind = iota // records answer the question
	lookupNoData                   // the name exists and has no such records
	lookupNoName                   // the name does not exist
)

// zone is everything the server answers from, apart from the challenge values. NewXip builds it once and nothing changes it afterwards, so handlers read it without a lock.
type zone struct {
	apex        string
	nameServers []string
	soa         *dns.SOA
	// records holds every stored record by canonical owner and type, owned by that canonical name; none of them is ever handed out without a copy, because replies are packed concurrently.
	records map[string]map[uint16][]dns.RR
	cuts    *zoneCuts
}

// newZone builds the zone from the configuration and from what the zone file declares (nil without a zone file), and checks that its built-in answers fit in a DNS message.
func newZone(domain, email string, nameServers []netip.Addr, file *zoneFile) (*zone, error) {
	apex, err := canonicalName(domain)
	if err != nil {
		return nil, fmt.Errorf("xip: domain %s: %w", domain, err)
	}
	if len(nameServers) == 0 {
		return nil, errors.New("xip: at least one name server is required")
	}
	rname, err := canonicalName(emailToRname(email))
	if err != nil {
		return nil, fmt.Errorf("xip: email %s cannot be the RNAME of the SOA record: %w", email, err)
	}

	z := &zone{
		apex:        apex,
		nameServers: nameServerNames(apex, len(nameServers)),
		records:     make(map[string]map[uint16][]dns.RR),
	}
	z.soa = &dns.SOA{
		Hdr:     header(apex, dns.TypeSOA, recordTTL),
		Ns:      z.nameServers[0],
		Mbox:    rname,
		Serial:  2024072600,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  recordTTL,
	}
	z.add(z.soa)
	for i, addr := range nameServers {
		z.add(&dns.NS{Hdr: header(apex, dns.TypeNS, recordTTL), Ns: z.nameServers[i]})
		z.add(&dns.A{Hdr: header(apex, dns.TypeA, recordTTL), A: addr.AsSlice()})
		z.add(&dns.A{Hdr: header(z.nameServers[i], dns.TypeA, recordTTL), A: addr.AsSlice()})
	}
	if file != nil {
		z.cuts = file.cuts
		for _, rr := range file.records {
			z.add(rr)
		}
	}

	if err := z.checkResponseSizes(); err != nil {
		return nil, err
	}
	return z, nil
}

// nameServerNames returns the names of the zone's own name servers, ns1 to nsN below the apex, in the order of their addresses.
func nameServerNames(apex string, count int) []string {
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("ns%d.%s", i+1, apex)
	}
	return names
}

func header(owner string, rrtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: owner, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
}

func (z *zone) add(rr dns.RR) {
	owner := rr.Header().Name
	sets := z.records[owner]
	if sets == nil {
		sets = make(map[uint16][]dns.RR)
		z.records[owner] = sets
	}
	sets[rr.Header().Rrtype] = append(sets[rr.Header().Rrtype], rr)
}

// checkResponseSizes refuses a configuration whose built-in answers at the apex, which grow with the list of name servers, would not fit in a DNS message; every other reply is bounded by construction or by the zone file's own checks.
func (z *zone) checkResponseSizes() error {
	qname := upperASCII(z.apex)
	nsSize, err := responseSize(qname, dns.TypeNS, ownedBy(qname, z.records[z.apex][dns.TypeNS]), nil, z.nameServerAddresses())
	if err := z.checkBuiltInAnswer(dns.TypeNS, nsSize, err); err != nil {
		return err
	}
	for _, rrtype := range []uint16{dns.TypeA, dns.TypeSOA} {
		size, err := answerSize(z.apex, z.records[z.apex][rrtype])
		if err := z.checkBuiltInAnswer(rrtype, size, err); err != nil {
			return err
		}
	}
	return nil
}

func (z *zone) checkBuiltInAnswer(rrtype uint16, size int, err error) error {
	if err != nil {
		return fmt.Errorf("xip: building the answer for %s %s: %w", z.apex, dns.Type(rrtype), err)
	}
	if size > maxResponseSize {
		return fmt.Errorf("xip: the answer for %s %s takes %d octets, more than the limit of %d octets for a DNS message; there are too many name servers for this domain", z.apex, dns.Type(rrtype), size, maxResponseSize)
	}
	return nil
}

// lookup answers a question whose name is inside the zone, outside every delegation and not the challenge name. name must be the canonical form of the question name (dns.CanonicalName): the handler needs that form for the cut and the challenge name before it gets here, and passing it in folds the case of a name once per query. The answer records are owned by the question name as asked and are the caller's to send. additional holds the name server addresses for NS at the apex and is nil otherwise.
func (z *zone) lookup(question dns.Question, name string) (kind lookupKind, answer, additional []dns.RR) {
	sets := z.records[name]
	if sets == nil {
		if addr, ok := addressIn(strings.TrimSuffix(name, z.apex)); ok {
			return addressAnswer(question, addr)
		}
		if canHaveChild(name) {
			return lookupNoData, nil, nil
		}
		return lookupNoName, nil, nil
	}

	cname := sets[dns.TypeCNAME]
	switch {
	case question.Qtype == dns.TypeANY && cname != nil:
		return lookupAnswer, ownedBy(question.Name, cname), nil
	case question.Qtype == dns.TypeANY:
		return lookupAnswer, []dns.RR{anyAnswer(question.Name, anyTTL)}, nil
	case sets[question.Qtype] != nil:
		if question.Qtype == dns.TypeNS && name == z.apex {
			additional = z.nameServerAddresses()
		}
		return lookupAnswer, ownedBy(question.Name, sets[question.Qtype]), additional
	case cname != nil:
		return lookupAnswer, ownedBy(question.Name, cname), nil
	}
	return lookupNoData, nil, nil
}

// addressAnswer answers at a name whose only record is the A record of the address it carries.
func addressAnswer(question dns.Question, addr netip.Addr) (lookupKind, []dns.RR, []dns.RR) {
	switch question.Qtype {
	case dns.TypeA:
		return lookupAnswer, []dns.RR{&dns.A{Hdr: header(question.Name, dns.TypeA, addressTTL), A: addr.AsSlice()}}, nil
	case dns.TypeANY:
		return lookupAnswer, []dns.RR{anyAnswer(question.Name, anyTTL)}, nil
	}
	return lookupNoData, nil, nil
}

// anyAnswer is the record of RFC 8482 section 4.2 that answers a query for ANY at a name with records.
func anyAnswer(owner string, ttl uint32) dns.RR {
	return &dns.HINFO{Hdr: header(owner, dns.TypeHINFO, ttl), Cpu: "RFC8482", Os: ""}
}

// canHaveChild reports whether a name that owns nothing exists all the same, as the parent a name below it may have: a name too long for any child is the only one the server can show to be empty below.
func canHaveChild(name string) bool {
	if len(name) <= maxParentPresentationLength {
		return true
	}
	var buf [maxNameWireLength]byte
	length, err := dns.PackDomainName(name, buf[:], 0, nil, false)
	// A name that does not pack into the octets of the longest name has no child either.
	return err == nil && length <= maxParentWireLength
}

// ownedBy returns copies of the stored records owned by name.
func ownedBy(name string, set []dns.RR) []dns.RR {
	records := make([]dns.RR, len(set))
	for i, rr := range set {
		records[i] = dns.Copy(rr)
		records[i].Header().Name = name
	}
	return records
}

// copies returns copies of stored records, nil for none.
func copies(set []dns.RR) []dns.RR {
	if len(set) == 0 {
		return nil
	}
	records := make([]dns.RR, len(set))
	for i, rr := range set {
		records[i] = dns.Copy(rr)
	}
	return records
}

// nameServerAddresses returns the A records of the zone's own name servers, for the additional section of the NS answer at the apex.
func (z *zone) nameServerAddresses() []dns.RR {
	var records []dns.RR
	for _, name := range z.nameServers {
		records = append(records, copies(z.records[name][dns.TypeA])...)
	}
	return records
}

// negativeTTL is the TTL RFC 2308 section 3 gives the SOA record of a negative answer: the smaller of its own TTL and its MINIMUM field.
func (z *zone) negativeTTL() uint32 {
	return min(z.soa.Hdr.Ttl, z.soa.Minttl)
}

// negativeAuthority is the authority section of every NODATA and NXDOMAIN reply: the zone's SOA record, owned by the apex, with the TTL given.
func (z *zone) negativeAuthority(ttl uint32) []dns.RR {
	soa := dns.Copy(z.soa)
	soa.Header().Ttl = ttl
	return []dns.RR{soa}
}
