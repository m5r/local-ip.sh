package xip

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// addressTTL is the TTL of the address a name carries: the answer follows from the name alone, and only a delegation added later at or above the name can change it.
const addressTTL uint32 = 86400

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
	apex string
	soa  *dns.SOA
	// records holds every stored record by canonical owner and type, owned by that canonical name; none of them is ever handed out without a copy, because replies are packed concurrently.
	records map[string]map[uint16][]dns.RR
	cuts    *zoneCuts
	// nameServerAddresses is the additional section of the NS answer at the apex.
	nameServerAddresses []dns.RR
}

// newZone builds the zone from what a zone file declares, which parseZoneFile has checked.
func newZone(file *zoneFile) *zone {
	z := &zone{
		apex:                file.cuts.apex,
		soa:                 file.soa,
		records:             make(map[string]map[uint16][]dns.RR),
		cuts:                file.cuts,
		nameServerAddresses: file.nameServerAddresses,
	}
	for _, rr := range file.records {
		z.add(rr)
	}
	return z
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
			additional = copies(z.nameServerAddresses)
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
