package xip

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

const zoneFileDefaultTTL = 300

// maxTTL is the largest TTL a record may have: RFC 2181 section 8 has a receiver treat a TTL with the most significant bit set as zero, so a larger value would not be served as written.
const maxTTL = 1<<31 - 1

// maxResponseSize is the largest reply the server may build, measured without an OPT record: a reply that does not fit in a DNS message once the OPT record of an EDNS query is added would be truncated even over TCP, leaving a resolver no transport to get it whole.
// The checks apply it wherever input without a bound of its own decides the size of a reply: the zone file and the challenge values.
const maxResponseSize = dns.MaxMsgSize - optRecordLength

const maxNameWireLength = 255

const maxLabelLength = 63

const unsupportedTypeMessage = "the zone file takes SOA and NS records at the apex, NS records for delegations, and A, AAAA, CAA, CNAME, MX, SRV and TXT records"

type delegation struct {
	nsRecords []dns.RR
	glue      []dns.RR
}

// zoneCuts holds the delegations of one zone. A nil *zoneCuts has no delegations.
type zoneCuts struct {
	apex string
	cuts map[string]delegation
}

// zoneFile is what a zone file declares: the delegations, and the records the server answers itself.
type zoneFile struct {
	cuts    *zoneCuts
	records []dns.RR // outside every delegation, in file order, owner and RDATA names canonical
	soa     *dns.SOA // one of records
	// nameServerAddresses are the A and AAAA records of the apex NS targets inside the zone, among records: the additional section of the NS answer at the apex, and the addresses no delegation may point back to.
	nameServerAddresses []dns.RR
}

// zoneServer describes the server that loads a zone file.
type zoneServer struct {
	origin        string
	challengeName string // reserved, and has no address
}

// zoneNames holds the names a zone file is checked against, all canonical.
type zoneNames struct {
	apex      string
	challenge string
}

// parseZoneFile reads the zone file content from r. file is used in error messages only.
// Every name is compared in its canonical wire form (see canonicalName), and the order of the checks decides which fault a file with several reports.
func parseZoneFile(r io.Reader, file string, server zoneServer) (*zoneFile, error) {
	names, err := newZoneNames(file, server)
	if err != nil {
		return nil, err
	}

	records, soa, err := readZoneRecords(r, file, names.apex)
	if err != nil {
		return nil, err
	}

	zc := &zoneCuts{apex: names.apex, cuts: make(map[string]delegation)}
	addressOwners := make(map[string]bool)
	for _, rr := range records {
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			ns := rr.(*dns.NS)
			if ns.Hdr.Name == names.apex {
				continue
			}
			d := zc.cuts[ns.Hdr.Name]
			d.nsRecords = append(d.nsRecords, ns)
			zc.cuts[ns.Hdr.Name] = d
		case dns.TypeA, dns.TypeAAAA:
			addressOwners[rr.Header().Name] = true
		}
	}

	if err := zc.checkDelegations(records, file, names.challenge, addressOwners); err != nil {
		return nil, err
	}
	if err := zc.checkApexNSTargets(records, file, names, addressOwners); err != nil {
		return nil, err
	}
	nameServerAddresses := apexNameServerAddresses(records, names)
	zoneRecords, err := zc.separateRecords(records, file, names, nameServerAddresses)
	if err != nil {
		return nil, err
	}
	if err := zc.checkTargets(zoneRecords, file, names); err != nil {
		return nil, err
	}
	if err := checkAnswerSizes(zoneRecords, file); err != nil {
		return nil, err
	}
	if err := checkApexNameServerAnswerSize(zoneRecords, nameServerAddresses, file, names.apex); err != nil {
		return nil, err
	}
	if err := zc.checkReferralSizes(file); err != nil {
		return nil, err
	}
	return &zoneFile{cuts: zc, records: zoneRecords, soa: soa, nameServerAddresses: nameServerAddresses}, nil
}

func newZoneNames(file string, server zoneServer) (zoneNames, error) {
	apex, err := canonicalName(server.origin)
	if err != nil {
		return zoneNames{}, fmt.Errorf("zone file %s: origin %q: %w", file, server.origin, err)
	}
	challenge, err := canonicalName(server.challengeName)
	if err != nil {
		return zoneNames{}, fmt.Errorf("zone file %s: challenge name %q: %w", file, server.challengeName, err)
	}
	return zoneNames{apex: apex, challenge: challenge}, nil
}

// labelsBelow returns the labels of a canonical name inside the zone in front of the apex, each with its dot, as addressIn takes them.
func (n zoneNames) labelsBelow(name string) string {
	return strings.TrimSuffix(name, n.apex)
}

func (n zoneNames) inside(name string) bool {
	return dns.IsSubDomain(n.apex, name)
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
	return fmt.Errorf("zone file %s: record %s %s: %s", file, hdr.Name, dns.Type(hdr.Rrtype), fmt.Sprintf(format, args...))
}

// readZoneRecords parses the file, canonicalises names and applies the rules that concern a record on its own or against the records before it, and those that need every record: one SOA record and at least one NS record at the apex.
func readZoneRecords(r io.Reader, file string, apex string) ([]dns.RR, *dns.SOA, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("reading zone file %s: %w", file, err)
	}
	if line, found := generateDirectiveLine(string(content)); found {
		return nil, nil, fmt.Errorf("zone file %s: line %d: $GENERATE is not supported", file, line)
	}

	zp := dns.NewZoneParser(bytes.NewReader(content), apex, file)
	zp.SetDefaultTTL(zoneFileDefaultTTL)

	var records []dns.RR
	var soa *dns.SOA
	apexNSRecords := 0
	seen := make(map[string]bool)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		hdr := rr.Header()
		owner, err := canonicalName(hdr.Name)
		if err != nil {
			return nil, nil, recordError(file, rr, "invalid owner name: %v", err)
		}
		hdr.Name = owner

		if hdr.Class != dns.ClassINET {
			return nil, nil, recordError(file, rr, "class %s is not supported, only IN", dns.ClassToString[hdr.Class])
		}
		switch hdr.Rrtype {
		case dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeMX, dns.TypeSRV, dns.TypeTXT:
		default:
			return nil, nil, recordError(file, rr, "type %s is not supported: %s", dns.Type(hdr.Rrtype), unsupportedTypeMessage)
		}
		if hdr.Ttl > maxTTL {
			return nil, nil, recordError(file, rr, "TTL %d is larger than %d: RFC 2181 section 8 has a receiver treat it as 0", hdr.Ttl, maxTTL)
		}
		// The parser accepts a record without RDATA, as used in dynamic updates, as the last line of a file and as `\# 0` anywhere; served, it would be meaningless. The check comes before the names of the RDATA are put in canonical form, which turns an empty name into the root.
		if hasEmptyRdata(rr) {
			return nil, nil, recordError(file, rr, "record has no data")
		}
		if err := canonicaliseRdataNames(rr); err != nil {
			return nil, nil, recordError(file, rr, "%v", err)
		}
		key, err := duplicateKey(rr)
		if err != nil {
			return nil, nil, recordError(file, rr, "cannot be encoded: %v", err)
		}
		if !dns.IsSubDomain(apex, owner) {
			return nil, nil, recordError(file, rr, "owner is outside the zone %s", apex)
		}
		if hdr.Rrtype == dns.TypeSOA && owner != apex {
			return nil, nil, recordError(file, rr, "an SOA record must be at the apex %s", apex)
		}
		if hdr.Rrtype == dns.TypeCNAME && owner == apex {
			return nil, nil, recordError(file, rr, "a CNAME record cannot be at the apex")
		}
		if hasWildcardLabel(owner) {
			return nil, nil, recordError(file, rr, "wildcard owners are not supported")
		}
		if seen[key] {
			return nil, nil, recordError(file, rr, "duplicate of an earlier record")
		}
		seen[key] = true
		if hdr.Rrtype == dns.TypeSOA && soa != nil {
			return nil, nil, recordError(file, rr, "the zone has exactly one SOA record, and an earlier one is declared")
		}
		for _, previous := range records {
			if previous.Header().Name == owner && previous.Header().Rrtype == hdr.Rrtype && previous.Header().Ttl != hdr.Ttl {
				return nil, nil, recordError(file, rr, "TTL %d differs from TTL %d of an earlier record with the same owner and type", hdr.Ttl, previous.Header().Ttl)
			}
		}
		switch record := rr.(type) {
		case *dns.SOA:
			soa = record
		case *dns.NS:
			if owner == apex {
				apexNSRecords++
			}
		}
		records = append(records, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, nil, fmt.Errorf("parsing zone file %s: %w", file, err)
	}
	if soa == nil {
		return nil, nil, fmt.Errorf("zone file %s: there is no SOA record at the apex %s", file, apex)
	}
	if apexNSRecords == 0 {
		return nil, nil, fmt.Errorf("zone file %s: there is no NS record at the apex %s: the zone needs at least one name server", file, apex)
	}
	return records, soa, nil
}

// generateDirectiveLine returns the number of the first line that begins, at the first column, with $GENERATE in any letter case followed by a space or a tab: the parser expands that directive by itself into records with a TTL of 3600 seconds whatever $TTL and the default TTL say, which would surprise the operator.
// It is a guard that catches the directive as anyone writes it, not a parser: a directive split with parentheses gets past it, and a continuation line or a line of a quoted string that begins so is refused although it is data; both are accepted costs of not repeating the library's lexer.
func generateDirectiveLine(content string) (int, bool) {
	for i, line := range strings.Split(content, "\n") {
		end := strings.IndexAny(line, " \t")
		if end >= 0 && strings.EqualFold(line[:end], "$GENERATE") {
			return i + 1, true
		}
	}
	return 0, false
}

// duplicateKey returns the record in wire format with its TTL set to 0, uncompressed: two records are duplicates when they would be sent the same apart from their TTL.
// The parser keeps TXT strings and CAA values as written, escapes included, so comparing parsed records would tell `"\097"` and `"a"` apart although they are the same on the wire.
// The parsed record stays the one that is stored: the library reads a CAA value back from the wire without escaping it, so a record unpacked from the wire would not pack to the same octets again.
func duplicateKey(rr dns.RR) (string, error) {
	keyed := dns.Copy(rr)
	keyed.Header().Ttl = 0
	// dns.Len is never less than the record's length; the packer refuses an empty octet string, such as an empty CAA value, that ends at the very end of its buffer, so the buffer gets one spare octet.
	buf := make([]byte, dns.Len(keyed)+1)
	length, err := dns.PackRR(keyed, buf, 0, nil, false)
	if err != nil {
		return "", err
	}
	return string(buf[:length]), nil
}

// canonicaliseRdataNames puts the names in the RDATA of an SOA, NS, CNAME, MX or SRV record in canonical form, so that the rules compare them with owners and the server sends them in lower case.
func canonicaliseRdataNames(rr dns.RR) error {
	switch record := rr.(type) {
	case *dns.SOA:
		if err := canonicaliseRdataName(&record.Ns, "MNAME"); err != nil {
			return err
		}
		return canonicaliseRdataName(&record.Mbox, "RNAME")
	case *dns.NS:
		return canonicaliseRdataName(&record.Ns, "name server name")
	case *dns.CNAME:
		return canonicaliseRdataName(&record.Target, "target name")
	case *dns.MX:
		return canonicaliseRdataName(&record.Mx, "target name")
	case *dns.SRV:
		return canonicaliseRdataName(&record.Target, "target name")
	}
	return nil
}

func canonicaliseRdataName(name *string, field string) error {
	canonical, err := canonicalName(*name)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	*name = canonical
	return nil
}

// checkDelegations applies the rules on cuts and their name servers.
func (zc *zoneCuts) checkDelegations(records []dns.RR, file string, challenge string, addresses map[string]bool) error {
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok || ns.Hdr.Name == zc.apex {
			continue
		}
		cut := ns.Hdr.Name
		if parent, nested := zc.enclosingCut(cut); nested {
			return recordError(file, rr, "delegation is nested below the delegation %s", parent)
		}
		if cut == challenge {
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

// checkApexNSTargets requires every name server of the zone named inside it to own an address record that this server answers with: outside every delegation, at a name that does not carry an address.
func (zc *zoneCuts) checkApexNSTargets(records []dns.RR, file string, names zoneNames, addresses map[string]bool) error {
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok || ns.Hdr.Name != names.apex || !names.inside(ns.Ns) {
			continue
		}
		if addr, carries := addressIn(names.labelsBelow(ns.Ns)); carries {
			return recordError(file, rr, "name server %s carries the address %s in its name: such a name resolves to that address and cannot own the address records of a name server", ns.Ns, addr)
		}
		if cut, _, delegated := zc.find(ns.Ns); delegated {
			return recordError(file, rr, "name server %s is at or below the delegation %s: a name server of the zone must be outside every delegation", ns.Ns, cut)
		}
		if !addresses[ns.Ns] {
			return recordError(file, rr, "name server %s is inside the zone and has no A or AAAA record", ns.Ns)
		}
	}
	return nil
}

// apexNameServerAddresses returns the A and then the AAAA records of each apex NS target inside the zone, in the order of the NS records and then of the file.
func apexNameServerAddresses(records []dns.RR, names zoneNames) []dns.RR {
	var addresses []dns.RR
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok || ns.Hdr.Name != names.apex || !names.inside(ns.Ns) {
			continue
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			for _, address := range records {
				if address.Header().Name == ns.Ns && address.Header().Rrtype == rrtype {
					addresses = append(addresses, address)
				}
			}
		}
	}
	return addresses
}

// separateRecords adds every address record inside a cut to the delegation it is glue for and returns the other records, the records of the zone, in file order.
// It applies the rules on records against the whole file, each record against all of them, in the order they are written, before the next record.
func (zc *zoneCuts) separateRecords(records []dns.RR, file string, names zoneNames, nameServerAddresses []dns.RR) ([]dns.RR, error) {
	cnames := make(map[string]int)
	others := make(map[string]int)
	for _, rr := range records {
		owner := rr.Header().Name
		if _, _, inCut := zc.find(owner); inCut {
			continue
		}
		if rr.Header().Rrtype == dns.TypeCNAME {
			cnames[owner]++
		} else {
			others[owner]++
		}
	}

	var zoneRecords []dns.RR
	for _, rr := range records {
		hdr := rr.Header()
		owner := hdr.Name
		if hdr.Rrtype == dns.TypeNS && owner != names.apex {
			continue
		}
		if cut, d, ok := zc.find(owner); ok {
			if err := zc.attachGlue(rr, file, cut, d, nameServerAddresses); err != nil {
				return nil, err
			}
			continue
		}
		if owner == names.challenge {
			return nil, recordError(file, rr, "%s is reserved: the server answers for it itself", owner)
		}
		if addr, ok := addressIn(names.labelsBelow(owner)); ok {
			return nil, recordError(file, rr, "%s carries the address %s and resolves to it: it cannot have records of its own", owner, addr)
		}
		if hdr.Rrtype == dns.TypeCNAME && cnames[owner] > 1 {
			return nil, recordError(file, rr, "%s has more than one CNAME record", owner)
		}
		if cnames[owner] > 0 && others[owner] > 0 {
			return nil, recordError(file, rr, "%s has a CNAME record and other records: a CNAME must be alone at its name", owner)
		}
		if cname, ok := rr.(*dns.CNAME); ok && names.inside(cname.Target) {
			return nil, recordError(file, rr, "CNAME target %s is inside the zone %s: only targets outside the zone are supported", cname.Target, names.apex)
		}
		zoneRecords = append(zoneRecords, rr)
	}
	return zoneRecords, nil
}

// attachGlue adds an address record inside the cut to its delegation, rejecting a record that is not glue or that points back at one of the zone's own name servers.
func (zc *zoneCuts) attachGlue(rr dns.RR, file string, cut string, d delegation, nameServerAddresses []dns.RR) error {
	owner := rr.Header().Name
	if rrtype := rr.Header().Rrtype; rrtype != dns.TypeA && rrtype != dns.TypeAAAA {
		return recordError(file, rr, "%s is at or below the delegation %s, where this server answers with a referral: only the addresses of its name servers can be declared there", owner, cut)
	}
	if !isNameServerOf(d, owner) {
		return recordError(file, rr, "address record is not glue: %s is not a name server of the delegation %s", owner, cut)
	}
	if addr, ok := glueAddress(rr); ok && slices.ContainsFunc(nameServerAddresses, func(own dns.RR) bool {
		ownAddr, ok := glueAddress(own)
		return ok && ownAddr == addr
	}) {
		return recordError(file, rr, "name server %s has the address %s, which is one of this zone's own name server addresses; the delegation would point back at this server", owner, addr)
	}
	d.glue = append(d.glue, rr)
	zc.cuts[cut] = d
	return nil
}

// checkTargets requires the target of an MX or SRV record that this server answers for to have an address and not to be an alias.
func (zc *zoneCuts) checkTargets(zoneRecords []dns.RR, file string, names zoneNames) error {
	aliases := make(map[string]bool)
	addressOwners := make(map[string]bool)
	for _, rr := range zoneRecords {
		switch rr.Header().Rrtype {
		case dns.TypeCNAME:
			aliases[rr.Header().Name] = true
		case dns.TypeA, dns.TypeAAAA:
			addressOwners[rr.Header().Name] = true
		}
	}

	for _, rr := range zoneRecords {
		var target string
		switch record := rr.(type) {
		case *dns.MX:
			target = record.Mx
		case *dns.SRV:
			target = record.Target
		default:
			continue
		}
		if !names.inside(target) {
			continue
		}
		if _, _, delegated := zc.find(target); delegated {
			continue
		}
		if aliases[target] {
			return recordError(file, rr, "target %s is an alias: the target of an MX or SRV record must not own a CNAME record", target)
		}
		if _, carriesAddress := addressIn(names.labelsBelow(target)); !carriesAddress && !addressOwners[target] {
			return recordError(file, rr, "target %s is inside the zone %s and has no address record", target, names.apex)
		}
	}
	return nil
}

// checkAnswerSizes measures the answer for every record set of the zone, in file order of its first record.
func checkAnswerSizes(zoneRecords []dns.RR, file string) error {
	type setKey struct {
		owner  string
		rrtype uint16
	}
	var order []setKey
	sets := make(map[setKey][]dns.RR)
	for _, rr := range zoneRecords {
		key := setKey{owner: rr.Header().Name, rrtype: rr.Header().Rrtype}
		if _, seen := sets[key]; !seen {
			order = append(order, key)
		}
		sets[key] = append(sets[key], rr)
	}

	for _, key := range order {
		size, err := answerSize(key.owner, sets[key])
		if err != nil {
			return fmt.Errorf("zone file %s: building the answer for %s %s: %w", file, key.owner, dns.Type(key.rrtype), err)
		}
		if size > maxResponseSize {
			return fmt.Errorf("zone file %s: the answer for %s %s takes %d octets, more than the limit of %d octets for a DNS message", file, key.owner, dns.Type(key.rrtype), size, maxResponseSize)
		}
	}
	return nil
}

// checkApexNameServerAnswerSize measures the answer for NS at the apex with the addresses of the name servers in its additional section, which checkAnswerSizes does not count.
func checkApexNameServerAnswerSize(zoneRecords, nameServerAddresses []dns.RR, file string, apex string) error {
	var apexNS []dns.RR
	for _, rr := range zoneRecords {
		if rr.Header().Name == apex && rr.Header().Rrtype == dns.TypeNS {
			apexNS = append(apexNS, rr)
		}
	}
	qname := upperASCII(apex)
	size, err := responseSize(qname, dns.TypeNS, ownedBy(qname, apexNS), nil, nameServerAddresses)
	if err != nil {
		return fmt.Errorf("zone file %s: building the answer for %s NS: %w", file, apex, err)
	}
	if size > maxResponseSize {
		return fmt.Errorf("zone file %s: the answer for %s NS with the addresses of its name servers takes %d octets, more than the limit of %d octets for a DNS message", file, apex, size, maxResponseSize)
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
		if size > maxResponseSize {
			return fmt.Errorf("zone file %s: delegation %s: the largest referral takes %d octets, more than the limit of %d octets for a DNS message", file, cut, size, maxResponseSize)
		}
	}
	return nil
}

// find returns the cut that covers name, if any.
// name must be canonical (ASCII lower case, fully qualified), as the handler and the loader already hold it, so that a query's name is folded in one place.
func (zc *zoneCuts) find(name string) (cut string, d delegation, ok bool) {
	if zc == nil || len(zc.cuts) == 0 {
		return "", delegation{}, false
	}
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
	for _, rr := range d.nsRecords {
		if rr.(*dns.NS).Ns == name {
			return true
		}
	}
	return false
}

func hasEmptyRdata(rr dns.RR) bool {
	switch record := rr.(type) {
	case *dns.SOA:
		return record.Ns == "" || record.Mbox == ""
	case *dns.NS:
		return record.Ns == ""
	case *dns.A:
		return record.A == nil
	case *dns.AAAA:
		return record.AAAA == nil
	case *dns.CNAME:
		return record.Target == ""
	case *dns.MX:
		return record.Mx == ""
	case *dns.SRV:
		return record.Target == ""
	case *dns.TXT:
		return len(record.Txt) == 0
	case *dns.CAA:
		return record.Tag == ""
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
	return responseSize(qname, dns.TypeA, nil, d.nsRecords, d.glue)
}

// answerSize packs the answer for a record set as the server sends it, owned by the question name, with the owner in ASCII upper case as the question: the stored names are in lower case and name compression matches case exactly, so this is the question whose answer compresses least.
func answerSize(owner string, set []dns.RR) (int, error) {
	qname := upperASCII(owner)
	answer := make([]dns.RR, len(set))
	for i, rr := range set {
		answer[i] = dns.Copy(rr)
		answer[i].Header().Name = qname
	}
	return responseSize(qname, set[0].Header().Rrtype, answer, nil, nil)
}

// responseSize packs a response to the question qname qtype with the given sections, compressed as the server sends it, and returns its length in octets.
func responseSize(qname string, qtype uint16, answer, authority, additional []dns.RR) (int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Answer = answer
	msg.Ns = authority
	msg.Extra = additional
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
