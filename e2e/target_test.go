package e2e

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
)

const asciiWhitespace = " \t\r\n\v\f"

type target struct {
	// name says what the target is in log lines and messages: the Fly app or the compose project.
	name   string
	domain string
	// dnsServers are the IPv4 addresses the zone file gives the name servers inside the zone, where the suite sends its DNS questions: the machine that runs the suite may have no IPv6.
	dnsServers []netip.Addr
	// webAddresses are the IPv4 addresses of the apex, where the suite reaches the website and the published certificate.
	webAddresses []netip.Addr
	// publiclyDelegated is whether the domain is delegated to the name servers on the public internet, so that public resolvers can answer for it.
	publiclyDelegated bool
	// roots verify the certificates the target serves and publishes.
	roots *x509.CertPool
	// soa is the zone file's SOA record, which every SOA record a name server sends is held to.
	soa *dns.SOA
	// apexNS is the NS record set of the apex, whose answer carries an additional section where every other declared set carries none.
	apexNS targetRecordSet
	// apexNSAdditional is that additional section: for each name server inside the zone, in the order of the NS records, its A records then its AAAA records, each in file order.
	apexNSAdditional []dns.RR
	delegations      []targetDelegation
	recordSets       []targetRecordSet
}

// targetSource is what a reader takes from a deployment's description for newTarget.
type targetSource struct {
	// path is the description's file, which every error names.
	path string
	// envKeys is the prefix that, followed by a variable's name, names the variable's place in the description.
	envKeys string
	name    string
	env     map[string]any
	// files maps the path at which the server reads a file the deployment delivers to the path of that file on this machine.
	files             map[string]string
	publiclyDelegated bool
	roots             *x509.CertPool
}

// targetDelegation is a zone cut declared in the target's zone file, as the suite reads it
// independently of the server.
type targetDelegation struct {
	cut         string
	nameServers []string
	glue        map[string][]netip.Addr
}

// targetRecordSet is a record set the target's zone file declares outside every delegation, which the server answers itself.
type targetRecordSet struct {
	owner  string
	rrtype uint16
	ttl    uint32
	// records are in the form an answer carries them: through a wire round trip, with the owner and the names in RDATA canonical.
	records []dns.RR
}

// targetZoneFile is what the suite expects from a zone file. The NS records of the apex are kept apart from the record sets: they are no cut, and their answer is checked by a case of its own.
type targetZoneFile struct {
	apexNS      targetRecordSet
	delegations []targetDelegation
	recordSets  []targetRecordSet
}

func (tg *target) zone() string {
	return dns.Fqdn(tg.domain)
}

// recordSet returns the record set the zone file declares at the owner, a canonical name, with the type, if any.
func (tg *target) recordSet(owner string, rrtype uint16) (targetRecordSet, bool) {
	i := slices.IndexFunc(tg.recordSets, func(set targetRecordSet) bool { return set.owner == owner && set.rrtype == rrtype })
	if i < 0 {
		return targetRecordSet{}, false
	}
	return tg.recordSets[i], true
}

// apexNSTargets are the names of the zone's name servers, in canonical form.
func (tg *target) apexNSTargets() []string {
	hosts := make([]string, len(tg.apexNS.records))
	for i, rr := range tg.apexNS.records {
		hosts[i] = rr.(*dns.NS).Ns
	}
	return hosts
}

// loadFlyTarget reads the target from a Fly config: a deployment on Fly is delegated on the public internet and serves certificates the system trusts.
func loadFlyTarget(configPath string) (*target, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading Fly config %s: %w", configPath, err)
	}

	var raw struct {
		App   any            `toml:"app"`
		Env   map[string]any `toml:"env"`
		Files []struct {
			GuestPath any `toml:"guest_path"`
			LocalPath any `toml:"local_path"`
		} `toml:"files"`
	}
	if err := toml.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("parsing Fly config %s: %w", configPath, err)
	}

	invalid := func(key, format string, args ...any) error {
		return fmt.Errorf("%s: %s: "+format, append([]any{configPath, key}, args...)...)
	}

	app, err := requiredString(raw.App, raw.App != nil)
	if err != nil {
		return nil, invalid("app", "%w", err)
	}

	files := make(map[string]string, len(raw.Files))
	for i, file := range raw.Files {
		guestPath, err := requiredString(file.GuestPath, file.GuestPath != nil)
		if err != nil {
			return nil, invalid(fmt.Sprintf("files[%d].guest_path", i), "%w", err)
		}
		localPath, err := requiredString(file.LocalPath, file.LocalPath != nil)
		if err != nil {
			return nil, invalid(fmt.Sprintf("files[%d].local_path", i), "%w", err)
		}
		if _, twice := files[guestPath]; twice {
			return nil, invalid(fmt.Sprintf("files[%d].guest_path", i), "%q is the guest path of an earlier entry too", guestPath)
		}
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Join(filepath.Dir(configPath), localPath)
		}
		files[guestPath] = localPath
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading the system's trusted roots for %s: %w", configPath, err)
	}
	return newTarget(targetSource{
		path:              configPath,
		envKeys:           "env.",
		name:              "Fly app " + app,
		env:               raw.Env,
		files:             files,
		publiclyDelegated: true,
		roots:             roots,
	})
}

// newTarget checks the server's environment and the zone file it is delivered, and turns them into the target the suite expects to find.
func newTarget(src targetSource) (*target, error) {
	invalid := func(variable, format string, args ...any) error {
		return fmt.Errorf("%s: %s%s: "+format, append([]any{src.path, src.envKeys, variable}, args...)...)
	}
	tg := &target{name: src.name, publiclyDelegated: src.publiclyDelegated, roots: src.roots}

	domain, err := requiredEnv(src.env, "XIP_DOMAIN")
	if err != nil {
		return nil, invalid("XIP_DOMAIN", "%w", err)
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return nil, invalid("XIP_DOMAIN", "is empty after removing the trailing dot")
	}
	if _, ok := dns.IsDomainName(domain); !ok {
		return nil, invalid("XIP_DOMAIN", "%q is not a valid domain name", domain)
	}
	tg.domain = domain

	zoneFile, err := requiredEnv(src.env, "XIP_ZONE_FILE")
	if err != nil {
		return nil, invalid("XIP_ZONE_FILE", "%w", err)
	}
	localPath, delivered := src.files[zoneFile]
	if !delivered {
		return nil, invalid("XIP_ZONE_FILE", "%q is not the path of a file the deployment delivers to the server", zoneFile)
	}
	zf, err := loadZoneFile(localPath, tg.zone())
	if err != nil {
		return nil, invalid("XIP_ZONE_FILE", "%w", err)
	}
	tg.apexNS = zf.apexNS
	tg.delegations = zf.delegations
	tg.recordSets = zf.recordSets
	if err := tg.readApex(); err != nil {
		return nil, invalid("XIP_ZONE_FILE", "zone file %s %w", localPath, err)
	}

	if err := checkProbes(tg); err != nil {
		return nil, fmt.Errorf("%s: %w", src.path, err)
	}
	if err := checkTransportSets(tg); err != nil {
		return nil, fmt.Errorf("%s: %w", src.path, err)
	}

	return tg, nil
}

// readApex takes from the zone file's records what the suite reaches the target through and holds the answers at the apex to: the SOA record, the addresses of the name servers inside the zone, and the addresses of the apex.
func (tg *target) readApex() error {
	zone := tg.zone()
	soa, _ := tg.recordSet(zone, dns.TypeSOA)
	if len(soa.records) != 1 {
		return fmt.Errorf("declares %d SOA records at the apex, want exactly one, which every SOA record a name server sends is held to", len(soa.records))
	}
	tg.soa = soa.records[0].(*dns.SOA)

	for _, host := range tg.apexNSTargets() {
		if !dns.IsSubDomain(zone, host) {
			continue
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			set, _ := tg.recordSet(host, rrtype)
			tg.apexNSAdditional = append(tg.apexNSAdditional, set.records...)
		}
		set, _ := tg.recordSet(host, dns.TypeA)
		for _, rr := range set.records {
			if addr, ok := address(rr); ok && !slices.Contains(tg.dnsServers, addr) {
				tg.dnsServers = append(tg.dnsServers, addr)
			}
		}
	}
	if len(tg.dnsServers) == 0 {
		return errors.New("gives no name server inside the zone an A record, so the suite has no IPv4 address to send its DNS questions to")
	}

	apexA, _ := tg.recordSet(zone, dns.TypeA)
	for _, rr := range apexA.records {
		if addr, ok := address(rr); ok {
			tg.webAddresses = append(tg.webAddresses, addr)
		}
	}
	if len(tg.webAddresses) == 0 {
		return errors.New("declares no A record at the apex, so the suite has no address to reach the website and the published certificate at")
	}
	return nil
}

// wireCanonicalName returns the name as it reads after a round trip through wire format,
// lower-cased: the zone parser keeps escapes as written, while names in responses arrive unpacked,
// so `\115ub` in the file must be expected as `sub`.
func wireCanonicalName(name string) (string, error) {
	buf := make([]byte, 255)
	if _, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false); err != nil {
		return "", fmt.Errorf("packing %q: %w", name, err)
	}
	unpacked, _, err := dns.UnpackDomainName(buf, 0)
	if err != nil {
		return "", fmt.Errorf("unpacking %q: %w", name, err)
	}
	return dns.CanonicalName(unpacked), nil
}

// comparableRecord returns a copy of a record from a zone file in the form an answer carries it: the strings of its RDATA as the library unpacks them, and its owner and the names in its RDATA canonical.
func comparableRecord(rr dns.RR) (dns.RR, error) {
	// dns.Len is never less than the record's length; the packer refuses an empty octet string, such as an empty CAA value, that ends at the very end of its buffer, so the buffer gets one spare octet.
	buf := make([]byte, dns.Len(rr)+1)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("packing %q: %w", rr, err)
	}
	unpacked, _, err := dns.UnpackRR(buf[:off], 0)
	if err != nil {
		return nil, fmt.Errorf("unpacking %q: %w", rr, err)
	}

	names := []*string{&unpacked.Header().Name}
	switch record := unpacked.(type) {
	case *dns.NS:
		names = append(names, &record.Ns)
	case *dns.CNAME:
		names = append(names, &record.Target)
	case *dns.MX:
		names = append(names, &record.Mx)
	case *dns.SRV:
		names = append(names, &record.Target)
	case *dns.SOA:
		names = append(names, &record.Ns, &record.Mbox)
	}
	for _, name := range names {
		canonical, err := wireCanonicalName(*name)
		if err != nil {
			return nil, fmt.Errorf("name %q of %q: %w", *name, rr, err)
		}
		*name = canonical
	}
	return unpacked, nil
}

// generateDirectiveLine returns the number of the first line that begins, at the first column, with $GENERATE in any letter case followed by a space or a tab, the same guard as the server's.
// It catches the directive as anyone writes it and is not a parser: a directive split with parentheses gets past it, and a continuation line or a line of a quoted string that begins so is refused although it is data; both are accepted costs of not repeating the library's lexer.
func generateDirectiveLine(content string) (int, bool) {
	for i, line := range strings.Split(content, "\n") {
		end := strings.IndexAny(line, " \t")
		if end >= 0 && strings.EqualFold(line[:end], "$GENERATE") {
			return i + 1, true
		}
	}
	return 0, false
}

// loadZoneFile reads from a zone file the NS records of the apex, the cuts, their name servers and the glue for them, and the record sets declared outside every delegation. It does not repeat the server's validation: the suite only needs to know what to expect.
func loadZoneFile(zoneFilePath string, zone string) (targetZoneFile, error) {
	content, err := os.ReadFile(zoneFilePath)
	if err != nil {
		return targetZoneFile{}, fmt.Errorf("reading zone file: %w", err)
	}
	// The server refuses a file with $GENERATE, so the records the parser would generate from it are none the suite may expect.
	if line, found := generateDirectiveLine(string(content)); found {
		return targetZoneFile{}, fmt.Errorf("zone file %s: line %d: $GENERATE is not supported", zoneFilePath, line)
	}

	zp := dns.NewZoneParser(bytes.NewReader(content), zone, zoneFilePath)
	zp.SetDefaultTTL(300)
	byCut := make(map[string]*targetDelegation)
	apexNS := targetRecordSet{owner: zone, rrtype: dns.TypeNS}
	var others []dns.RR
	for parsed, ok := zp.Next(); ok; parsed, ok = zp.Next() {
		rr, err := comparableRecord(parsed)
		if err != nil {
			return targetZoneFile{}, fmt.Errorf("zone file %s: %w", zoneFilePath, err)
		}
		owner := rr.Header().Name
		ns, isNS := rr.(*dns.NS)
		switch {
		case isNS && owner == zone:
			// The NS records of the apex name the zone's own name servers: the server answers for the apex itself, so it is no cut and no referral may be expected there.
			if len(apexNS.records) == 0 {
				apexNS.ttl = rr.Header().Ttl
			}
			apexNS.records = append(apexNS.records, rr)
		case isNS:
			d, ok := byCut[owner]
			if !ok {
				d = &targetDelegation{cut: owner, glue: make(map[string][]netip.Addr)}
				byCut[owner] = d
			}
			d.nameServers = append(d.nameServers, ns.Ns)
		default:
			others = append(others, rr)
		}
	}
	if err := zp.Err(); err != nil {
		return targetZoneFile{}, fmt.Errorf("parsing zone file: %w", err)
	}

	cuts := slices.Sorted(maps.Keys(byCut))
	insideCut := func(name string) bool {
		return slices.ContainsFunc(cuts, func(cut string) bool { return dns.IsSubDomain(cut, name) })
	}

	addresses := make(map[string][]netip.Addr)
	var recordSets []targetRecordSet
	for _, rr := range others {
		hdr := rr.Header()
		if insideCut(hdr.Name) {
			if addr, ok := address(rr); ok {
				addresses[hdr.Name] = append(addresses[hdr.Name], addr)
			}
			continue
		}
		i := slices.IndexFunc(recordSets, func(set targetRecordSet) bool { return set.owner == hdr.Name && set.rrtype == hdr.Rrtype })
		if i < 0 {
			recordSets = append(recordSets, targetRecordSet{owner: hdr.Name, rrtype: hdr.Rrtype, ttl: hdr.Ttl})
			i = len(recordSets) - 1
		}
		recordSets[i].records = append(recordSets[i].records, rr)
	}

	delegations := make([]targetDelegation, 0, len(byCut))
	for _, cut := range cuts {
		d := byCut[cut]
		for _, nameServer := range d.nameServers {
			if dns.IsSubDomain(cut, nameServer) && len(addresses[nameServer]) > 0 {
				d.glue[nameServer] = addresses[nameServer]
			}
		}
		delegations = append(delegations, *d)
	}
	return targetZoneFile{apexNS: apexNS, delegations: delegations, recordSets: recordSets}, nil
}

// address returns the address of an A or AAAA record, an IPv4 address of an A record unmapped.
func address(rr dns.RR) (netip.Addr, bool) {
	switch record := rr.(type) {
	case *dns.A:
		addr, ok := netip.AddrFromSlice(record.A)
		return addr.Unmap(), ok
	case *dns.AAAA:
		return netip.AddrFromSlice(record.AAAA)
	}
	return netip.Addr{}, false
}

func requiredEnv(env map[string]any, key string) (string, error) {
	value, present := env[key]
	return requiredString(value, present)
}

func requiredString(value any, present bool) (string, error) {
	if !present {
		return "", errors.New("is required")
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("must be a string, got %T", value)
	}
	s = strings.Trim(s, asciiWhitespace)
	if s == "" {
		return "", errors.New("must not be empty")
	}
	return s, nil
}

func TestLoadProductionConfig(t *testing.T) {
	tg, err := loadFlyTarget(filepath.Join("..", "fly.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if tg.name != "Fly app local-ip" {
		t.Errorf("name = %q, want %q", tg.name, "Fly app local-ip")
	}
	if tg.domain != "local-ip.sh" {
		t.Errorf("domain = %q, want %q", tg.domain, "local-ip.sh")
	}
	want := []netip.Addr{netip.MustParseAddr("137.66.40.11"), netip.MustParseAddr("137.66.40.12")}
	if !slices.Equal(tg.dnsServers, want) {
		t.Errorf("dnsServers = %v, want %v", tg.dnsServers, want)
	}
	if !slices.Equal(tg.webAddresses, want) {
		t.Errorf("webAddresses = %v, want %v", tg.webAddresses, want)
	}
	if !tg.publiclyDelegated {
		t.Error("publiclyDelegated = false, want true")
	}
	assertRecords(t, "SOA", []dns.RR{tg.soa}, []string{`local-ip.sh. 3600 IN SOA ns1.local-ip.sh. admin.local-ip.sh. 2026112301 900 900 1800 3600`})
	assertRecords(t, "apex NS", tg.apexNS.records, []string{`local-ip.sh. 3600 IN NS ns1.local-ip.sh.`, `local-ip.sh. 3600 IN NS ns2.local-ip.sh.`})
	assertRecords(t, "apex NS additional", tg.apexNSAdditional, []string{`ns1.local-ip.sh. 3600 IN A 137.66.40.11`, `ns2.local-ip.sh. 3600 IN A 137.66.40.12`})
	assertDelegations(t, tg.delegations, nil)
	assertRecordSets(t, tg.recordSets, [][]string{
		{`local-ip.sh. 3600 IN SOA ns1.local-ip.sh. admin.local-ip.sh. 2026112301 900 900 1800 3600`},
		{`ns1.local-ip.sh. 3600 IN A 137.66.40.11`},
		{`ns2.local-ip.sh. 3600 IN A 137.66.40.12`},
		{`local-ip.sh. 3600 IN A 137.66.40.11`, `local-ip.sh. 3600 IN A 137.66.40.12`},
		{`local-ip.sh. 300 IN MX 10 mail.mial.net.`},
		{`local-ip.sh. 300 IN TXT "v=spf1 mx -all"`},
		{`202411e._domainkey.local-ip.sh. 300 IN TXT "v=DKIM1; k=ed25519; h=sha256; p=Xic3wKt0G+05OJw4q9U5FImcGnvKcMK5chBgYljJv8c="`},
		{`202411r._domainkey.local-ip.sh. 300 IN TXT "v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2y9b1q/Of6doBMq4f16YJkM9BSMAdiNCyQhy1BcEVG9XpIObaJzhRWddhAPB6Awz/QqnCkx51AXuMDgKIsv2Cs87+jJoILdJ2T6HhS05kZj5FHBKMNctgcFzN2XRhXXpIVLWbA9Ef7takTa2AO5+qCT0M1xkumNQEXc/znTuaWS86e766hLA06a" "7pBwriJj4ceb5V6/q5fvfVq+EgJnk8WQ9DQRs4VjHaSVN0fscRzzJsZAQpa6KqmSLiXzM+NktGN40EZGqFrvvGcfdE+jEa++rePixXgKsETZCR32tKCNCELzbdTGchu01F6vZVxT/AGNfxzFWs9tuXdiltYmhbwIDAQAB"`},
		{`_dmarc.local-ip.sh. 300 IN TXT "v=DMARC1; p=reject; rua=mailto:postmaster@local-ip.sh"`},
		{`_smtp._tls.local-ip.sh. 300 IN TXT "v=TLSRPTv1; rua=mailto:postmaster@local-ip.sh"`},
	})
	set, ok := tg.recordSet("202411r._domainkey.local-ip.sh.", dns.TypeTXT)
	if !ok {
		return
	}
	var lengths []int
	for _, rr := range set.records {
		for _, s := range rr.(*dns.TXT).Txt {
			lengths = append(lengths, len(s))
		}
	}
	if len(set.records) != 1 || !slices.Equal(lengths, []int{255, 165}) {
		t.Errorf("DKIM record set has %d records with strings of %v octets, want one record of two strings of 255 and 165 octets", len(set.records), lengths)
	}
}

// assertRecords compares records with the expected ones, given in zone file syntax with absolute names, in order.
func assertRecords(t *testing.T, what string, got []dns.RR, want []string) {
	t.Helper()
	gotRecords := make([]string, len(got))
	for i, rr := range got {
		gotRecords[i] = rr.String()
	}
	wantRecords := make([]string, len(want))
	for i, s := range want {
		rr, err := comparableRecord(mustRR(t, s))
		if err != nil {
			t.Fatal(err)
		}
		wantRecords[i] = rr.String()
	}
	if !slices.Equal(gotRecords, wantRecords) {
		t.Errorf("%s = %q, want %q", what, gotRecords, wantRecords)
	}
}

// assertRecordSets compares the record sets with the expected ones, each given as its records in zone file syntax with absolute names, in order.
func assertRecordSets(t *testing.T, got []targetRecordSet, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d record sets, want %d", len(got), len(want))
	}
	for i, set := range got {
		var records []string
		for _, rr := range set.records {
			hdr := rr.Header()
			if hdr.Name != set.owner || hdr.Rrtype != set.rrtype || hdr.Ttl != set.ttl {
				t.Errorf("record set %d is %s %s TTL %d but holds the record %q", i, set.owner, dns.Type(set.rrtype), set.ttl, rr)
			}
			records = append(records, rr.String())
		}
		if i >= len(want) {
			t.Errorf("unexpected record set %d: %q", i, records)
			continue
		}
		var wantRecords []string
		for _, s := range want[i] {
			rr, err := comparableRecord(mustRR(t, s))
			if err != nil {
				t.Fatal(err)
			}
			wantRecords = append(wantRecords, rr.String())
		}
		if !slices.Equal(records, wantRecords) {
			t.Errorf("record set %d = %q, want %q", i, records, wantRecords)
		}
	}
	for i := len(got); i < len(want); i++ {
		t.Errorf("missing record set %d: %q", i, want[i])
	}
}

// TestRigZoneFile holds the rig's zone file to the records at the apex, the record sets and the delegation the suite's cases rely on.
func TestRigZoneFile(t *testing.T) {
	zf, err := loadZoneFile(filepath.Join("rig", "zone"), "local-ip.test.")
	if err != nil {
		t.Fatal(err)
	}
	assertRecords(t, "apex NS", zf.apexNS.records, []string{`local-ip.test. 7200 IN NS dns-a.local-ip.test.`})
	assertDelegations(t, zf.delegations, []targetDelegation{{
		cut:         "e2e-delegated.local-ip.test.",
		nameServers: []string{"ns1.e2e-delegated.local-ip.test."},
		glue:        map[string][]netip.Addr{"ns1.e2e-delegated.local-ip.test.": {netip.MustParseAddr("192.0.2.53")}},
	}})
	assertRecordSets(t, zf.recordSets, [][]string{
		{`local-ip.test. 1800 IN SOA dns-a.local-ip.test. hostmaster.local-ip.test. 2026112301 7200 600 86400 120`},
		{`dns-a.local-ip.test. 1200 IN A 10.253.53.53`},
		{`dns-a.local-ip.test. 1200 IN AAAA 2001:db8:53::53`},
		{`local-ip.test. 600 IN A 10.253.53.53`},
		{`e2e-records.local-ip.test. 300 IN A 192.0.2.10`},
		{`e2e-records.local-ip.test. 300 IN AAAA 2001:db8::10`},
		{`e2e-records.local-ip.test. 300 IN TXT "local-ip.sh e2e" "second string"`},
		{`e2e-records.local-ip.test. 300 IN MX 10 mail.example.net.`},
		{`e2e-records.local-ip.test. 300 IN CAA 0 issue ";"`},
		{`e2e-alias.local-ip.test. 600 IN CNAME target.example.net.`},
		{`_e2e._tcp.local-ip.test. 300 IN SRV 0 0 443 target.example.net.`},
		{`local-ip.test. 300 IN TXT "local-ip.sh test instance"`},
		rigTXTRecords(udpTXTLabel, 4),
		rigTXTRecords(tcpTXTLabel, 12),
	})
	tg := &target{domain: "local-ip.test", recordSets: zf.recordSets}
	for _, label := range []string{udpTXTLabel, tcpTXTLabel} {
		set, ok := tg.txtSetAt(label)
		if !ok {
			t.Errorf("no TXT set at %s, want one for the transport cases", label)
			continue
		}
		var sizes []string
		for _, form := range []struct{ compress, withOPT bool }{{true, false}, {false, false}, {true, true}, {false, true}} {
			n, err := replySize(set, form.compress, form.withOPT)
			if err != nil {
				t.Fatal(err)
			}
			sizes = append(sizes, fmt.Sprintf("compressed %t with OPT %t: %d", form.compress, form.withOPT, n))
		}
		t.Logf("reply sizes for %s: %s", set.owner, strings.Join(sizes, ", "))
	}
}

// rigTXTRecords spells the TXT set the rig's zone file declares at the label: n records, each of one string of 180 octets that starts with its position.
func rigTXTRecords(label string, n int) []string {
	records := make([]string, n)
	for i := range n {
		prefix := fmt.Sprintf("%s record %d of %d ", label, i+1, n)
		records[i] = fmt.Sprintf(`%s.local-ip.test. 300 IN TXT "%s%s"`, label, prefix, strings.Repeat("x", 180-len(prefix)))
	}
	return records
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "fly.toml")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func flyConfig(app string, env map[string]string) string {
	var b strings.Builder
	if app != "" {
		fmt.Fprintf(&b, "app = %s\n", app)
	}
	b.WriteString("[env]\n")
	for _, key := range slices.Sorted(maps.Keys(env)) {
		fmt.Fprintf(&b, "%s = %s\n", key, env[key])
	}
	return b.String()
}

// validEnv is the environment of a target for example.com whose zone file is delivered by zoneFileEntry; an override of "" removes the variable.
func validEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"XIP_DOMAIN":    `"example.com"`,
		"XIP_ZONE_FILE": `"/etc/local-ip.zone"`,
	}
	for k, v := range overrides {
		if v == "" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	return env
}

const zoneFileEntry = "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n"

// minimalZone is the least a target's zone file for example.com holds: its SOA record, a name server inside the zone with an address, and an address of the apex. Its names are absolute and its TTLs written, so that it means the same after any $ORIGIN or $TTL of the lines in front of it.
const minimalZone = "example.com. 3600 SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300\nexample.com. 3600 NS ns1.example.com.\nns1.example.com. 3600 A 192.0.2.53\nexample.com. 3600 A 192.0.2.80\n"

// minimalSets are the record sets of minimalZone, in its order.
var minimalSets = [][]string{
	{`example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300`},
	{`ns1.example.com. 3600 IN A 192.0.2.53`},
	{`example.com. 3600 IN A 192.0.2.80`},
}

// writeTarget writes a Fly config with the environment of validEnv and the overrides, and the zone file it delivers, and returns the config's path.
func writeTarget(t *testing.T, overrides map[string]string, zone string) string {
	t.Helper()
	configPath := writeConfig(t, flyConfig(`"a"`, validEnv(overrides))+"\n"+zoneFileEntry)
	zonesDir := filepath.Join(filepath.Dir(configPath), "zones")
	if err := os.Mkdir(zonesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeZoneFile(t, zonesDir, "test.zone", zone)
	return configPath
}

func TestLoadTargetNormalisesValues(t *testing.T) {
	configPath := writeConfig(t, flyConfig(`"  my-app  "`, validEnv(map[string]string{
		"XIP_DOMAIN":    `" Example.COM. "`,
		"XIP_ZONE_FILE": `" /etc/local-ip.zone "`,
	}))+"\n"+zoneFileEntry)
	zonesDir := filepath.Join(filepath.Dir(configPath), "zones")
	if err := os.Mkdir(zonesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeZoneFile(t, zonesDir, "test.zone", minimalZone)

	tg, err := loadFlyTarget(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if tg.name != "Fly app my-app" {
		t.Errorf("name = %q, want %q", tg.name, "Fly app my-app")
	}
	if tg.domain != "example.com" {
		t.Errorf("domain = %q, want %q", tg.domain, "example.com")
	}
	if tg.zone() != "example.com." {
		t.Errorf("zone = %q, want %q", tg.zone(), "example.com.")
	}
}

func TestLoadTargetRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		app  string
		env  map[string]string
		key  string
	}{
		{name: "app missing", app: "", env: validEnv(nil), key: "app"},
		{name: "app empty", app: `"  "`, env: validEnv(nil), key: "app"},
		{name: "app not a string", app: `3`, env: validEnv(nil), key: "app"},
		{name: "domain missing", app: `"a"`, env: validEnv(map[string]string{"XIP_DOMAIN": ""}), key: "XIP_DOMAIN"},
		{name: "domain empty", app: `"a"`, env: validEnv(map[string]string{"XIP_DOMAIN": `" "`}), key: "XIP_DOMAIN"},
		{name: "domain only a dot", app: `"a"`, env: validEnv(map[string]string{"XIP_DOMAIN": `"."`}), key: "XIP_DOMAIN"},
		{name: "domain with empty label", app: `"a"`, env: validEnv(map[string]string{"XIP_DOMAIN": `"a..b"`}), key: "XIP_DOMAIN"},
		{name: "zone file missing", app: `"a"`, env: validEnv(map[string]string{"XIP_ZONE_FILE": ""}), key: "XIP_ZONE_FILE"},
		{name: "zone file empty", app: `"a"`, env: validEnv(map[string]string{"XIP_ZONE_FILE": `" "`}), key: "XIP_ZONE_FILE"},
		{name: "zone file not a string", app: `"a"`, env: validEnv(map[string]string{"XIP_ZONE_FILE": `true`}), key: "XIP_ZONE_FILE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, flyConfig(tt.app, tt.env))

			_, err := loadFlyTarget(configPath)
			if err == nil {
				t.Fatal("loadFlyTarget succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error %q does not name the key %q", err, tt.key)
			}
			if !strings.Contains(err.Error(), configPath) {
				t.Errorf("error %q does not name the file %q", err, configPath)
			}
		})
	}
}

// TestLoadTargetApex holds the target reader to what it takes from the records at the apex: where the suite sends its DNS questions and reaches the website, and what the answers to SOA and NS at the apex must carry.
func TestLoadTargetApex(t *testing.T) {
	const soa = "$TTL 300\n@ 3600 SOA ns1 hostmaster 1 7200 900 1209600 300\n"
	tests := []struct {
		name           string
		zone           string
		wantDNSServers []string
		wantWeb        []string
		wantAdditional []string
		wantErr        []string
	}{
		{
			name:           "the A records of the name servers inside the zone in the order of the NS records, their AAAA records in the additional section only",
			zone:           soa + "@ 3600 NS ns2\n@ 3600 NS ns.other.test.\n@ 3600 NS NS1\nns1 3600 A 192.0.2.1\nns2 3600 AAAA 2001:db8::2\nns1 3600 AAAA 2001:db8::1\nns2 3600 A 192.0.2.2\nns2 3600 A 192.0.2.3\n@ 300 A 192.0.2.80\n@ 300 A 192.0.2.81\n@ 300 AAAA 2001:db8::80\n",
			wantDNSServers: []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"},
			wantWeb:        []string{"192.0.2.80", "192.0.2.81"},
			wantAdditional: []string{
				"ns2.example.com. 3600 IN A 192.0.2.2", "ns2.example.com. 3600 IN A 192.0.2.3", "ns2.example.com. 3600 IN AAAA 2001:db8::2",
				"ns1.example.com. 3600 IN A 192.0.2.1", "ns1.example.com. 3600 IN AAAA 2001:db8::1",
			},
		},
		{
			name:           "an address two name servers share is asked once",
			zone:           soa + "@ NS ns1\n@ NS ns2\nns1 A 192.0.2.1\nns2 A 192.0.2.1\n@ A 192.0.2.80\n",
			wantDNSServers: []string{"192.0.2.1"},
			wantWeb:        []string{"192.0.2.80"},
			wantAdditional: []string{"ns1.example.com. 300 IN A 192.0.2.1", "ns2.example.com. 300 IN A 192.0.2.1"},
		},
		{
			name:    "no SOA record",
			zone:    "@ NS ns1\nns1 A 192.0.2.1\n@ A 192.0.2.80\n",
			wantErr: []string{"declares 0 SOA records at the apex, want exactly one"},
		},
		{
			name:    "two SOA records",
			zone:    soa + "@ 3600 SOA ns1 hostmaster 2 7200 900 1209600 300\n@ NS ns1\nns1 A 192.0.2.1\n@ A 192.0.2.80\n",
			wantErr: []string{"declares 2 SOA records at the apex, want exactly one"},
		},
		{
			name:    "only name servers outside the zone",
			zone:    soa + "@ NS ns.other.test.\n@ A 192.0.2.80\n",
			wantErr: []string{"gives no name server inside the zone an A record"},
		},
		{
			name:    "a name server inside the zone with an AAAA record alone",
			zone:    soa + "@ NS ns1\nns1 AAAA 2001:db8::1\n@ A 192.0.2.80\n",
			wantErr: []string{"gives no name server inside the zone an A record"},
		},
		{
			name:    "no NS record at the apex",
			zone:    soa + "ns1 A 192.0.2.1\n@ A 192.0.2.80\n",
			wantErr: []string{"gives no name server inside the zone an A record"},
		},
		{
			name:    "no A record at the apex",
			zone:    soa + "@ NS ns1\nns1 A 192.0.2.1\n@ AAAA 2001:db8::80\n",
			wantErr: []string{"declares no A record at the apex"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTarget(t, nil, tt.zone)
			tg, err := loadFlyTarget(configPath)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("loadFlyTarget succeeded, want an error")
				}
				for _, want := range append([]string{configPath, "env.XIP_ZONE_FILE", "test.zone"}, tt.wantErr...) {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var dnsServers, web []string
			for _, addr := range tg.dnsServers {
				dnsServers = append(dnsServers, addr.String())
			}
			for _, addr := range tg.webAddresses {
				web = append(web, addr.String())
			}
			if !slices.Equal(dnsServers, tt.wantDNSServers) {
				t.Errorf("dnsServers = %v, want %v", dnsServers, tt.wantDNSServers)
			}
			if !slices.Equal(web, tt.wantWeb) {
				t.Errorf("webAddresses = %v, want %v", web, tt.wantWeb)
			}
			assertRecords(t, "apex NS additional", tg.apexNSAdditional, tt.wantAdditional)
		})
	}
}

func assertDelegations(t *testing.T, got, want []targetDelegation) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d delegations %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].cut != want[i].cut {
			t.Errorf("delegation %d cut = %q, want %q", i, got[i].cut, want[i].cut)
		}
		if !slices.Equal(got[i].nameServers, want[i].nameServers) {
			t.Errorf("delegation %s name servers = %v, want %v", want[i].cut, got[i].nameServers, want[i].nameServers)
		}
		if !maps.EqualFunc(got[i].glue, want[i].glue, slices.Equal) {
			t.Errorf("delegation %s glue = %v, want %v", want[i].cut, got[i].glue, want[i].glue)
		}
	}
}

func writeZoneFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTargetZoneFile(t *testing.T) {
	const zoneFile = `"/etc/local-ip.zone"`
	const validZone = "Sub NS NS1.Sub\nns1.sub A 192.0.2.1\nns1.sub AAAA 2001:db8::1\nsub NS ns.other.test.\n"
	validWant := []targetDelegation{{
		cut:         "sub.example.com.",
		nameServers: []string{"ns1.sub.example.com.", "ns.other.test."},
		glue:        map[string][]netip.Addr{"ns1.sub.example.com.": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}},
	}}

	tests := []struct {
		name    string
		zoneEnv string
		files   string
		// zone is followed by minimalZone in the file, so that the target is complete, and wantSets by minimalSets.
		zone     string
		want     []targetDelegation
		wantSets [][]string
		// wantApexNS is the NS set of the apex when the zone declares NS records at the apex of its own.
		wantApexNS []string
		wantErr    []string
	}{
		{
			name:    "records outside every delegation are record sets in file order, with the glue left to its cut",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "@ TXT \"v=spf1 -all\"\n" + validZone + "www A 192.0.2.80\n@ MX 20 www\n@ MX 10 mail.other.test.\nwww AAAA 2001:db8::80\nalias CNAME target.other.test.\n_sip._tcp SRV 0 5 5060 sip.other.test.\n@ CAA 0 issue \"letsencrypt.org\"\n",
			want:    validWant,
			wantSets: [][]string{
				{`example.com. 300 IN TXT "v=spf1 -all"`},
				{`www.example.com. 300 IN A 192.0.2.80`},
				{`example.com. 300 IN MX 20 www.example.com.`, `example.com. 300 IN MX 10 mail.other.test.`},
				{`www.example.com. 300 IN AAAA 2001:db8::80`},
				{`alias.example.com. 300 IN CNAME target.other.test.`},
				{`_sip._tcp.example.com. 300 IN SRV 0 5 5060 sip.other.test.`},
				{`example.com. 300 IN CAA 0 issue "letsencrypt.org"`},
			},
		},
		{
			name:    "owners and targets are canonical, and a record of two strings stays one record",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "UPPER TXT \"one\" \"two\"\nesc\\065ped MX 10 Mail.Other.TEST.\nAlias CNAME Target.Other.Test.\n",
			wantSets: [][]string{
				{`upper.example.com. 300 IN TXT "one" "two"`},
				{`escaped.example.com. 300 IN MX 10 mail.other.test.`},
				{`alias.example.com. 300 IN CNAME target.other.test.`},
			},
		},
		{
			name:    "a TXT string longer than 255 octets arrives as two strings",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "long TXT \"" + strings.Repeat("a", 300) + "\"\n",
			wantSets: [][]string{
				{`long.example.com. 300 IN TXT "` + strings.Repeat("a", 255) + `" "` + strings.Repeat("a", 45) + `"`},
			},
		},
		{
			name:    "TTLs come from the record, then $TTL, then the default of 300 seconds",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "a TXT \"default\"\nb 60 TXT \"own\"\n$TTL 120\nc TXT \"directive\"\n",
			wantSets: [][]string{
				{`a.example.com. 300 IN TXT "default"`},
				{`b.example.com. 60 IN TXT "own"`},
				{`c.example.com. 120 IN TXT "directive"`},
			},
		},
		{
			name:    "without $TTL a record without a TTL inherits the TTL of the record before it",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "a TXT \"default\"\nb 600 TXT \"own\"\nc TXT \"inherited\"\n",
			wantSets: [][]string{
				{`a.example.com. 300 IN TXT "default"`},
				{`b.example.com. 600 IN TXT "own"`},
				{`c.example.com. 600 IN TXT "inherited"`},
			},
		},
		{
			name:    "a record above a cut is a record set and a record inside a cut that is not glue is not",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    validZone + "parent TXT \"above\"\nchild.parent NS ns.other.test.\nsub TXT \"inside\"\nx.sub A 192.0.2.9\n",
			want: append([]targetDelegation{{
				cut:         "child.parent.example.com.",
				nameServers: []string{"ns.other.test."},
				glue:        map[string][]netip.Addr{},
			}}, validWant...),
			wantSets: [][]string{
				{`parent.example.com. 300 IN TXT "above"`},
			},
		},
		{
			name:    "NS records at the apex are the apex NS set in file order, neither a cut nor a record set",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "@ 3600 NS ns.other.test.\n@ 300 TXT \"apex\"\n",
			wantSets: [][]string{
				{`example.com. 300 IN TXT "apex"`},
			},
			wantApexNS: []string{`example.com. 3600 IN NS ns.other.test.`, `example.com. 3600 IN NS ns1.example.com.`},
		},
		{
			name:    "no XIP_ZONE_FILE",
			files:   zoneFileEntry,
			zone:    "; complete\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "is required"},
		},
		{
			name:    "empty XIP_ZONE_FILE",
			zoneEnv: `""`,
			files:   zoneFileEntry,
			zone:    "; complete\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "must not be empty"},
		},
		{
			name:    "local path relative to the config directory",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/other\"\nlocal_path = \"other.zone\"\n\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    validZone,
			want:    validWant,
		},
		{
			name:    "names spelled with decimal escapes are expected in their plain form",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    `\115ub NS \110s1.\115ub` + "\n" + `ns1.sub A 192.0.2.1` + "\n" + `ns1.\115ub AAAA 2001:db8::1` + "\n" + `sub NS ns.\111ther.test.` + "\n",
			want:    validWant,
		},
		{
			name:    "zone file without delegations",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    "; nothing delegated\n",
		},
		{
			name:    "no [[files]] entry",
			zoneEnv: zoneFile,
			wantErr: []string{"env.XIP_ZONE_FILE", `"/etc/local-ip.zone" is not the path of a file the deployment delivers`},
		},
		{
			name:    "no [[files]] entry with the guest path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/other.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    validZone,
			wantErr: []string{"env.XIP_ZONE_FILE", `"/etc/local-ip.zone" is not the path of a file the deployment delivers`},
		},
		{
			name:    "two [[files]] entries with the guest path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    validZone,
			wantErr: []string{"files[1].guest_path", "of an earlier entry too"},
		},
		{
			name:    "empty local path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"  \"\n",
			wantErr: []string{"files[0].local_path", "must not be empty"},
		},
		{
			name:    "a guest path that is not a string",
			files:   "[[files]]\nguest_path = 1\nlocal_path = \"zones/test.zone\"\n",
			wantErr: []string{"files[0].guest_path", "must be a string"},
		},
		{
			name:    "missing zone file",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/missing.zone\"\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "missing.zone"},
		},
		{
			name:    "unparsable zone file",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    "sub NS ns1.sub\nns1.sub A not-an-address\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "test.zone", "not-an-address"},
		},
		{
			name:    "$GENERATE in upper case",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "www TXT \"x\"\n$GENERATE 1-3 host$ A 192.0.2.$\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "test.zone: line 2: $GENERATE is not supported"},
		},
		{
			name:    "$GENERATE in lower case",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "www TXT \"x\"\n\n$generate 1-3 host$ A 192.0.2.$\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "test.zone: line 3: $GENERATE is not supported"},
		},
		{
			name:     "a name and a TXT string that contain $GENERATE",
			zoneEnv:  zoneFile,
			files:    zoneFileEntry,
			zone:     "x$GENERATE TXT \"x\"\nwww TXT \"$GENERATE 1-3 host$ A 192.0.2.$\"\n",
			wantSets: [][]string{{`x$generate.example.com. 300 IN TXT "x"`}, {`www.example.com. 300 IN TXT "$GENERATE 1-3 host$ A 192.0.2.$"`}},
		},
		{
			name:     "$ORIGIN moves the owners of the records after it",
			zoneEnv:  zoneFile,
			files:    zoneFileEntry,
			zone:     "www TXT \"x\"\n$ORIGIN sub.example.com.\nwww TXT \"y\"\n",
			wantSets: [][]string{{`www.example.com. 300 IN TXT "x"`}, {`www.sub.example.com. 300 IN TXT "y"`}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, flyConfig(`"a"`, validEnv(map[string]string{"XIP_ZONE_FILE": tt.zoneEnv}))+"\n"+tt.files)
			if tt.zone != "" {
				zonesDir := filepath.Join(filepath.Dir(configPath), "zones")
				if err := os.Mkdir(zonesDir, 0o700); err != nil {
					t.Fatal(err)
				}
				writeZoneFile(t, zonesDir, "test.zone", tt.zone+minimalZone)
			}

			tg, err := loadFlyTarget(configPath)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("loadFlyTarget succeeded, want an error")
				}
				for _, want := range append([]string{configPath}, tt.wantErr...) {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertDelegations(t, tg.delegations, tt.want)
			assertRecordSets(t, tg.recordSets, slices.Concat(tt.wantSets, minimalSets))
			wantApexNS := tt.wantApexNS
			if wantApexNS == nil {
				wantApexNS = []string{`example.com. 3600 IN NS ns1.example.com.`}
			}
			assertRecords(t, "apex NS", tg.apexNS.records, wantApexNS)
		})
	}
}

// wireReply hands back what the client hands the checks for an answer that carries rdata as its RDATA octets: the reply packed and unpacked again.
// The library reads CAA values and TXT strings from the wire differently from how it parses them from zone file text, so a reply built from text would not show what a live answer looks like.
func wireReply(t *testing.T, qname string, rrtype uint16, ttl uint32, rdata []byte) *dns.Msg {
	t.Helper()
	reply := new(dns.Msg)
	reply.SetQuestion(qname, rrtype)
	reply.Response = true
	reply.Authoritative = true
	reply.Answer = []dns.RR{&dns.RFC3597{
		Hdr:   dns.RR_Header{Name: qname, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl},
		Rdata: hex.EncodeToString(rdata),
	}}
	octets, err := reply.Pack()
	if err != nil {
		t.Fatalf("packing the reply: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(octets); err != nil {
		t.Fatalf("unpacking the reply: %v", err)
	}
	return resp
}

func caaRDATA(flag uint8, tag, value string) []byte {
	return slices.Concat([]byte{flag, byte(len(tag))}, []byte(tag), []byte(value))
}

func txtRDATA(text string) []byte {
	return slices.Concat([]byte{byte(len(text))}, []byte(text))
}

func TestLoadedRecordSetIsCheckedAgainstAnswersOnTheWire(t *testing.T) {
	const backslashed = `a\097b`
	tests := []struct {
		name     string
		zone     string
		rrtype   uint16
		declared string
		accepted []byte
		rejected []byte
	}{
		{
			name:     "an empty CAA value loads and matches only an empty value",
			zone:     `www CAA 0 issue ""`,
			rrtype:   dns.TypeCAA,
			declared: `flag 0, tag "issue", value ""`,
			accepted: caaRDATA(0, "issue", ""),
			rejected: caaRDATA(0, "issue", ";"),
		},
		{
			name:     "a CAA value with an escaped backslash matches its six octets and not the unescaped aab",
			zone:     `www CAA 0 issue "a\\097\098"`,
			rrtype:   dns.TypeCAA,
			declared: `flag 0, tag "issue", value "a\\097b"`,
			accepted: caaRDATA(0, "issue", backslashed),
			rejected: caaRDATA(0, "issue", "aab"),
		},
		{
			name:     "a TXT string with an escaped backslash matches its six octets and not the unescaped aab",
			zone:     `www TXT "a\\097\098"`,
			rrtype:   dns.TypeTXT,
			accepted: txtRDATA(backslashed),
			rejected: txtRDATA("aab"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg, err := loadFlyTarget(writeTarget(t, nil, tt.zone+"\n"+minimalZone))
			if err != nil {
				t.Fatal(err)
			}
			set, ok := tg.recordSet("www.example.com.", tt.rrtype)
			if !ok || len(set.records) != 1 {
				t.Fatalf("record sets = %+v, want one set of one %s record at www.example.com.", tg.recordSets, dns.Type(tt.rrtype))
			}
			if tt.declared != "" {
				fields, err := rdataFields(set.records[0])
				if err != nil {
					t.Fatal(err)
				}
				if fields != tt.declared {
					t.Errorf("declared record = %s, want %s", fields, tt.declared)
				}
			}

			if err := checkRecordSet(set, wireReply(t, "www.example.com.", tt.rrtype, set.ttl, tt.accepted)); err != nil {
				t.Errorf("check rejected the answer that carries the declared octets %q: %v", tt.accepted, err)
			}
			if err := checkRecordSet(set, wireReply(t, "www.example.com.", tt.rrtype, set.ttl, tt.rejected)); err == nil {
				t.Errorf("check accepted the answer that carries the octets %q, want it rejected", tt.rejected)
			}
		})
	}
}

func TestLoadTargetRejectsZoneFileThatClaimsAProbeName(t *testing.T) {
	const reserved = "reserved for the suite's probes"
	tests := []struct {
		name    string
		zone    string
		wantErr []string
	}{
		{name: "a record at the unknown name", zone: "nope A 192.0.2.80\n", wantErr: []string{"the name nope.example.com.", `"unknown name"`, reserved, "declares nope.example.com. A there"}},
		{name: "a record of a type the probe does not ask for at a numeric name", zone: "13 TXT \"x\"\n", wantErr: []string{"the name 13.example.com.", `"one number"`, reserved, "declares 13.example.com. TXT there"}},
		{name: "a record at the longest name that can have a child", zone: nameOfWireLength("example.com.", 253) + " TXT \"x\"\n", wantErr: []string{`"longest name that can have a child"`, reserved, "TXT there"}},
		{name: "a delegation of the address probe", zone: "10-11-12-13 NS ns.other.test.\n", wantErr: []string{"the name 10-11-12-13.example.com.", `"dashed"`, reserved, "delegates it or a name above it: 10-11-12-13.example.com. NS"}},
		{name: "a delegation above a numeric probe", zone: "12.13 NS ns.other.test.\n", wantErr: []string{"the name 10.11.12.13.example.com.", reserved, "delegates it or a name above it: 12.13.example.com. NS"}},
		{name: "a delegation above the probe with labels after the address", zone: "app NS ns.other.test.\n", wantErr: []string{"the name 10-11-12-13.app.example.com.", reserved, "delegates it or a name above it: app.example.com. NS"}},
		{name: "a delegation of the round trip through the address alone", zone: "127-0-0-1 NS ns.other.test.\n", wantErr: []string{"the name 127-0-0-1.example.com.", "the certificate round trip through 127-0-0-1.example.com", reserved, "delegates it or a name above it: 127-0-0-1.example.com. NS"}},
		{name: "a delegation of the round trip through a name in front of the address", zone: "e2e-app-127-0-0-1 NS ns.other.test.\n", wantErr: []string{"the name e2e-app-127-0-0-1.example.com.", "the certificate round trip through e2e-app-127-0-0-1.example.com", reserved, "delegates it or a name above it: e2e-app-127-0-0-1.example.com. NS"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTarget(t, nil, tt.zone+minimalZone)

			_, err := loadFlyTarget(configPath)
			if err == nil {
				t.Fatal("loadFlyTarget succeeded, want an error")
			}
			for _, want := range append([]string{configPath}, tt.wantErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestLoadTargetChecksTransportSets(t *testing.T) {
	txtSet := func(label string, n, octets int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "%s TXT \"%d%s\"\n", label, i, strings.Repeat("x", octets-1))
		}
		return b.String()
	}
	tests := []struct {
		name    string
		zone    string
		wantErr []string
	}{
		{name: "accepts sets of the sizes the cases rely on", zone: txtSet(udpTXTLabel, 4, 180) + txtSet(tcpTXTLabel, 12, 180)},
		{name: "accepts a zone file without the sets", zone: "www A 192.0.2.80\n"},
		{name: "rejects a set at the UDP label that fits a reply without EDNS", zone: txtSet(udpTXTLabel, 2, 180), wantErr: []string{"e2e-txt-udp.example.com.", "without EDNS, want more than 512"}},
		{name: "rejects a set at the UDP label that does not fit a reply with EDNS", zone: txtSet(udpTXTLabel, 6, 180), wantErr: []string{"e2e-txt-udp.example.com.", "with EDNS, want less than 1232"}},
		{name: "rejects a set at the TCP label that fits a reply with EDNS", zone: txtSet(tcpTXTLabel, 4, 180), wantErr: []string{"e2e-txt-tcp.example.com.", "with EDNS, want more than 1232"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTarget(t, nil, tt.zone+minimalZone)

			_, err := loadFlyTarget(configPath)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("loadFlyTarget refused the zone file: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("loadFlyTarget succeeded, want an error")
			}
			for _, want := range append([]string{configPath}, tt.wantErr...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestOutsideNames(t *testing.T) {
	long := strings.Repeat("a", 63)
	longX := "x" + strings.Repeat("a", 62)
	tests := []struct {
		zone          string
		wantUnrelated string
		wantSibling   string
	}{
		{zone: "example.com.", wantUnrelated: "example.net.", wantSibling: "xexample.com."},
		{zone: "com.", wantUnrelated: "example.net.", wantSibling: "xcom."},
		{zone: "local-ip.sh.", wantUnrelated: "example.com.", wantSibling: "xlocal-ip.sh."},
		{zone: "xip-staging.local-ip.sh.", wantUnrelated: "example.com.", wantSibling: "xxip-staging.local-ip.sh."},
		{zone: long + ".example.test.", wantUnrelated: "example.com.", wantSibling: "x" + long[1:] + ".example.test."},
		{zone: longX + ".example.test.", wantUnrelated: "example.com.", wantSibling: "y" + longX[1:] + ".example.test."},
	}

	for _, tt := range tests {
		t.Run("outside "+tt.zone, func(t *testing.T) {
			unrelated, sibling := outsideNames(tt.zone)
			if unrelated != tt.wantUnrelated || sibling != tt.wantSibling {
				t.Errorf("outsideNames(%q) = %q, %q, want %q, %q", tt.zone, unrelated, sibling, tt.wantUnrelated, tt.wantSibling)
			}
			for _, name := range []string{unrelated, sibling} {
				if _, ok := dns.IsDomainName(name); !ok {
					t.Errorf("%q is not a domain name", name)
				}
				if dns.IsSubDomain(tt.zone, name) {
					t.Errorf("%q is inside the zone %s", name, tt.zone)
				}
			}
		})
	}
}
