package xip

import (
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

const zoneFileDefaultTTL = 300

// maxReferralSize is the largest referral the server may send. Responses are never truncated and
// the server does not listen on TCP, so a referral must fit in a classic 512-octet UDP response.
// This limit goes away when responses can be truncated and retried over TCP.
const maxReferralSize = dns.MinMsgSize

const maxNameWireLength = 255

const maxLabelLength = 63

type delegation struct {
	nameServers []dns.RR
	glue        []dns.RR
}

// zoneCuts holds the delegations of one zone. A nil *zoneCuts has no delegations.
type zoneCuts struct {
	apex string
	cuts map[string]delegation
}

// zoneServer describes the server that loads a zone file: its zone apex, the names that must not
// be delegated and the addresses of its own name servers, which no delegation may point back to.
type zoneServer struct {
	origin    string
	reserved  []string
	addresses []netip.Addr
}

// parseDelegations reads the zone file content from r. file is used in error messages only.
// Every name is compared in its canonical wire form (see canonicalName).
func parseDelegations(r io.Reader, file string, server zoneServer) (*zoneCuts, error) {
	apex, err := canonicalName(server.origin)
	if err != nil {
		return nil, fmt.Errorf("zone file %s: origin %q: %w", file, server.origin, err)
	}
	reserved := make(map[string]bool, len(server.reserved))
	for _, name := range server.reserved {
		canonical, err := canonicalName(name)
		if err != nil {
			return nil, fmt.Errorf("zone file %s: reserved name %q: %w", file, name, err)
		}
		reserved[canonical] = true
	}

	records, err := readDelegationRecords(r, file, apex)
	if err != nil {
		return nil, err
	}

	zc := &zoneCuts{apex: apex, cuts: make(map[string]delegation)}
	addresses := make(map[string]bool)
	for _, rr := range records {
		if ns, ok := rr.(*dns.NS); ok {
			d := zc.cuts[ns.Hdr.Name]
			d.nameServers = append(d.nameServers, ns)
			zc.cuts[ns.Hdr.Name] = d
		} else {
			addresses[rr.Header().Name] = true
		}
	}

	if err := zc.checkNameServers(records, file, reserved, addresses); err != nil {
		return nil, err
	}
	if err := zc.attachGlue(records, file, server.addresses); err != nil {
		return nil, err
	}
	if err := zc.checkReferralSizes(file); err != nil {
		return nil, err
	}
	return zc, nil
}

// canonicalName returns the name as it reads after a round trip through wire format, lower-cased.
// The zone parser keeps escapes as written, so `\115ub` and `sub` would otherwise be different
// names; the unpacked form is the one query names arrive in.
func canonicalName(name string) (string, error) {
	buf := make([]byte, maxNameWireLength)
	if _, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false); err != nil {
		return "", fmt.Errorf("packing %q: %w", name, err)
	}
	unpacked, _, err := dns.UnpackDomainName(buf, 0)
	if err != nil {
		return "", fmt.Errorf("unpacking %q: %w", name, err)
	}
	return dns.CanonicalName(unpacked), nil
}

func recordError(file string, rr dns.RR, format string, args ...any) error {
	hdr := rr.Header()
	return fmt.Errorf("zone file %s: record %s %s: %s", file, hdr.Name, dns.TypeToString[hdr.Rrtype], fmt.Sprintf(format, args...))
}

// readDelegationRecords parses the file, canonicalises names and applies the rules that concern a
// record on its own or against the records before it (R1 to R4, R10 and R11).
func readDelegationRecords(r io.Reader, file string, apex string) ([]dns.RR, error) {
	zp := dns.NewZoneParser(r, apex, file)
	zp.SetDefaultTTL(zoneFileDefaultTTL)

	var records []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		hdr := rr.Header()
		owner, err := canonicalName(hdr.Name)
		if err != nil {
			return nil, recordError(file, rr, "invalid owner name: %v", err)
		}
		hdr.Name = owner

		if hdr.Class != dns.ClassINET {
			return nil, recordError(file, rr, "class %s is not supported, only IN", dns.ClassToString[hdr.Class])
		}
		switch hdr.Rrtype {
		case dns.TypeNS, dns.TypeA, dns.TypeAAAA:
		default:
			return nil, recordError(file, rr, "only delegations are supported: NS records below the apex and their A/AAAA glue")
		}
		// The parser accepts a record without RDATA, as used in dynamic updates; served as glue or as
		// an NS target it would be meaningless.
		if hasEmptyRdata(rr) {
			return nil, recordError(file, rr, "record has no data")
		}
		if ns, isNS := rr.(*dns.NS); isNS {
			target, err := canonicalName(ns.Ns)
			if err != nil {
				return nil, recordError(file, rr, "invalid name server name: %v", err)
			}
			ns.Ns = target
		}
		if hdr.Name == apex || !dns.IsSubDomain(apex, hdr.Name) {
			return nil, recordError(file, rr, "owner must be strictly below the apex %s", apex)
		}
		if hasWildcardLabel(hdr.Name) {
			return nil, recordError(file, rr, "wildcard owners are not supported")
		}
		for _, previous := range records {
			if dns.IsDuplicate(previous, rr) {
				return nil, recordError(file, rr, "duplicate of an earlier record")
			}
			if previous.Header().Name == hdr.Name && previous.Header().Rrtype == hdr.Rrtype && previous.Header().Ttl != hdr.Ttl {
				return nil, recordError(file, rr, "TTL %d differs from TTL %d of an earlier record with the same owner and type", hdr.Ttl, previous.Header().Ttl)
			}
		}
		records = append(records, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parsing zone file %s: %w", file, err)
	}
	return records, nil
}

// checkNameServers applies the rules on cuts and their name servers (R5 to R8).
func (zc *zoneCuts) checkNameServers(records []dns.RR, file string, reserved map[string]bool, addresses map[string]bool) error {
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		cut := ns.Hdr.Name
		if parent, nested := zc.enclosingCut(cut); nested {
			return recordError(file, rr, "delegation is nested below the delegation %s", parent)
		}
		if reserved[cut] {
			return recordError(file, rr, "%s is reserved and cannot be delegated", cut)
		}
		if !dns.IsSubDomain(cut, ns.Ns) {
			if dns.IsSubDomain(zc.apex, ns.Ns) {
				return recordError(file, rr, "name server %s is inside the zone %s but outside the delegated zone %s; it must be inside the delegated zone (with glue) or outside the zone", ns.Ns, zc.apex, cut)
			}
			continue
		}
		if !addresses[ns.Ns] {
			return recordError(file, rr, "name server %s is inside the delegated zone and has no A or AAAA glue record", ns.Ns)
		}
	}
	return nil
}

// attachGlue adds every address record to the delegation it is glue for, rejecting any that is not
// glue (R9) or that points back at one of this server's own name servers (R13).
func (zc *zoneCuts) attachGlue(records []dns.RR, file string, ownAddresses []netip.Addr) error {
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeNS {
			continue
		}
		owner := rr.Header().Name
		cut, d, ok := zc.find(owner)
		if !ok {
			return recordError(file, rr, "address record is not inside any delegation; only glue for delegated name servers is supported")
		}
		if !isNameServerOf(d, owner) {
			return recordError(file, rr, "address record is not glue: %s is not a name server of the delegation %s", owner, cut)
		}
		if addr, ok := glueAddress(rr); ok && slices.ContainsFunc(ownAddresses, func(own netip.Addr) bool { return own.Unmap() == addr }) {
			return recordError(file, rr, "name server %s has the address %s, which is one of this server's own name server addresses; the delegation would point back at this server", owner, addr)
		}
		d.glue = append(d.glue, rr)
		zc.cuts[cut] = d
	}
	return nil
}

func glueAddress(rr dns.RR) (netip.Addr, bool) {
	var addr netip.Addr
	var ok bool
	switch record := rr.(type) {
	case *dns.A:
		addr, ok = netip.AddrFromSlice(record.A)
	case *dns.AAAA:
		addr, ok = netip.AddrFromSlice(record.AAAA)
	}
	return addr.Unmap(), ok
}

func (zc *zoneCuts) checkReferralSizes(file string) error {
	for _, cut := range slices.Sorted(maps.Keys(zc.cuts)) {
		size, err := largestReferralSize(cut, zc.cuts[cut])
		if err != nil {
			return fmt.Errorf("zone file %s: delegation %s: building the largest referral: %w", file, cut, err)
		}
		if size > maxReferralSize {
			return fmt.Errorf("zone file %s: delegation %s: the largest referral takes %d octets, more than the limit of %d octets for a UDP response", file, cut, size, maxReferralSize)
		}
	}
	return nil
}

// find returns the cut that covers name, if any. name is expected in the form query names arrive
// in from the wire; only its case is normalised.
func (zc *zoneCuts) find(name string) (cut string, d delegation, ok bool) {
	if zc == nil || len(zc.cuts) == 0 {
		return "", delegation{}, false
	}
	name = dns.CanonicalName(name)
	for off, end := 0, false; !end; off, end = dns.NextLabel(name, off) {
		candidate := name[off:]
		if candidate == zc.apex {
			break
		}
		if d, ok := zc.cuts[candidate]; ok {
			return candidate, d, true
		}
	}
	return "", delegation{}, false
}

func (zc *zoneCuts) sortedCuts() []string {
	if zc == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(zc.cuts))
}

func (zc *zoneCuts) enclosingCut(cut string) (string, bool) {
	parentOffset, end := dns.NextLabel(cut, 0)
	if end {
		return "", false
	}
	parent, _, ok := zc.find(cut[parentOffset:])
	return parent, ok
}

func isNameServerOf(d delegation, name string) bool {
	for _, rr := range d.nameServers {
		if rr.(*dns.NS).Ns == name {
			return true
		}
	}
	return false
}

func hasEmptyRdata(rr dns.RR) bool {
	switch record := rr.(type) {
	case *dns.NS:
		return record.Ns == ""
	case *dns.A:
		return record.A == nil
	case *dns.AAAA:
		return record.AAAA == nil
	}
	return false
}

func hasWildcardLabel(name string) bool {
	for _, label := range dns.SplitDomainName(name) {
		if label == "*" {
			return true
		}
	}
	return false
}

// largestReferralSize packs the referral for the longest name that can exist inside the cut.
func largestReferralSize(cut string, d delegation) (int, error) {
	qname, err := referralProbeName(cut)
	if err != nil {
		return 0, err
	}
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Ns = append(msg.Ns, d.nameServers...)
	msg.Extra = append(msg.Extra, d.glue...)
	msg.Compress = true
	packed, err := msg.Pack()
	if err != nil {
		return 0, err
	}
	return len(packed), nil
}

// referralProbeName is the longest name inside the cut, in upper case. The stored records are in
// lower case and name compression matches case exactly, so a lower-case probe would let them
// compress against the question and understate the referral for a query in any other case.
func referralProbeName(cut string) (string, error) {
	name, err := longestNameIn(cut)
	if err != nil {
		return "", err
	}
	return upperASCII(name), nil
}

// upperASCII upper-cases ASCII letters only; strings.ToUpper would also map non-ASCII octets and
// can change the length of the name.
func upperASCII(name string) string {
	b := []byte(name)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func longestNameIn(cut string) (string, error) {
	buf := make([]byte, maxNameWireLength)
	wireLength, err := dns.PackDomainName(cut, buf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("packing %s: %w", cut, err)
	}

	var prefix strings.Builder
	remaining := maxNameWireLength - wireLength
	for remaining >= 2 {
		length := min(maxLabelLength, remaining-1)
		// A remainder of one octet cannot hold a label, so give one octet to the next label instead.
		if remaining-(length+1) == 1 {
			length--
		}
		prefix.WriteString(strings.Repeat("x", length))
		prefix.WriteByte('.')
		remaining -= length + 1
	}
	return prefix.String() + cut, nil
}
