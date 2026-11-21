package e2e

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/mail"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/pelletier/go-toml/v2"
)

//go:embed testdata/*.pem
var stagingRootFiles embed.FS

const asciiWhitespace = " \t\r\n\v\f"

type target struct {
	app         string
	domain      string
	nameServers []netip.Addr
	email       string
	stagingCA   bool
	roots       *x509.CertPool
	rname       string
	delegations []targetDelegation
	recordSets  []targetRecordSet
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

// targetZoneFile is what the suite expects from a zone file.
type targetZoneFile struct {
	delegations []targetDelegation
	recordSets  []targetRecordSet
}

func (tg *target) zone() string {
	return dns.Fqdn(tg.domain)
}

func (tg *target) nameServerHosts() []string {
	hosts := make([]string, len(tg.nameServers))
	for i := range tg.nameServers {
		hosts[i] = fmt.Sprintf("ns%d.%s", i+1, tg.zone())
	}
	return hosts
}

// soaRname is the RNAME the server must send: the mailbox as emailToRname spells it, through the wire round trip and the lower-casing the server applies, so that a character the library escapes is spelled as the server spells it.
func (tg *target) soaRname() string {
	return tg.rname
}

func emailToRname(email string) string {
	at := strings.LastIndex(email, "@")
	local := strings.ReplaceAll(email[:at], ".", `\.`)
	return local + "." + email[at+1:] + "."
}

func loadTarget(configPath string) (*target, error) {
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

	tg := &target{}

	app, err := requiredString(raw.App, raw.App != nil)
	if err != nil {
		return nil, invalid("app", "%w", err)
	}
	tg.app = app

	domain, err := requiredEnv(raw.Env, "XIP_DOMAIN")
	if err != nil {
		return nil, invalid("env.XIP_DOMAIN", "%w", err)
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return nil, invalid("env.XIP_DOMAIN", "is empty after removing the trailing dot")
	}
	if _, ok := dns.IsDomainName(domain); !ok {
		return nil, invalid("env.XIP_DOMAIN", "%q is not a valid domain name", domain)
	}
	tg.domain = domain

	nameServers, err := requiredEnv(raw.Env, "XIP_NAMESERVERS")
	if err != nil {
		return nil, invalid("env.XIP_NAMESERVERS", "%w", err)
	}
	for i, element := range strings.Split(nameServers, ",") {
		element = strings.Trim(element, asciiWhitespace)
		if element == "" {
			return nil, invalid("env.XIP_NAMESERVERS", "element %d is empty", i+1)
		}
		addr, err := netip.ParseAddr(element)
		if err != nil {
			return nil, invalid("env.XIP_NAMESERVERS", "element %d: %w", i+1, err)
		}
		if !addr.Is4() {
			return nil, invalid("env.XIP_NAMESERVERS", "element %d: %s is not an IPv4 address", i+1, addr)
		}
		tg.nameServers = append(tg.nameServers, addr)
	}

	email, err := requiredEnv(raw.Env, "XIP_EMAIL")
	if err != nil {
		return nil, invalid("env.XIP_EMAIL", "%w", err)
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return nil, invalid("env.XIP_EMAIL", "%w", err)
	}
	if parsed.Address != email {
		return nil, invalid("env.XIP_EMAIL", "%q must be a bare address, not %q", parsed.Address, email)
	}
	tg.email = email
	tg.rname, err = wireCanonicalName(emailToRname(email))
	if err != nil {
		return nil, invalid("env.XIP_EMAIL", "%q cannot be the RNAME of the SOA record: %w", email, err)
	}

	staging, present, err := optionalEnv(raw.Env, "XIP_STAGING")
	if err != nil {
		return nil, invalid("env.XIP_STAGING", "%w", err)
	}
	if present {
		tg.stagingCA, err = strconv.ParseBool(staging)
		if err != nil {
			return nil, invalid("env.XIP_STAGING", "%w", err)
		}
	}

	if tg.stagingCA {
		tg.roots, err = stagingRootPool()
	} else {
		tg.roots, err = x509.SystemCertPool()
	}
	if err != nil {
		return nil, fmt.Errorf("loading trust roots for %s: %w", configPath, err)
	}

	zoneFile, present, err := optionalEnv(raw.Env, "XIP_ZONE_FILE")
	if err != nil {
		return nil, invalid("env.XIP_ZONE_FILE", "%w", err)
	}
	if present && zoneFile != "" {
		var localPaths []string
		for _, file := range raw.Files {
			guestPath, ok := file.GuestPath.(string)
			if !ok || strings.Trim(guestPath, asciiWhitespace) != zoneFile {
				continue
			}
			localPath, _ := file.LocalPath.(string)
			localPaths = append(localPaths, strings.Trim(localPath, asciiWhitespace))
		}
		if len(localPaths) != 1 || localPaths[0] == "" {
			return nil, invalid("env.XIP_ZONE_FILE", "%q must be the guest_path of exactly one [[files]] entry with a non-empty local_path, found %d entries with local paths %q", zoneFile, len(localPaths), localPaths)
		}
		localPath := localPaths[0]
		if !filepath.IsAbs(localPath) {
			localPath = filepath.Join(filepath.Dir(configPath), localPath)
		}
		zf, err := loadZoneFile(localPath, tg.zone())
		if err != nil {
			return nil, fmt.Errorf("%s: env.XIP_ZONE_FILE: %w", configPath, err)
		}
		tg.delegations = zf.delegations
		tg.recordSets = zf.recordSets
	}

	if err := checkProbes(tg); err != nil {
		return nil, fmt.Errorf("%s: %w", configPath, err)
	}
	if err := checkTransportSets(tg); err != nil {
		return nil, fmt.Errorf("%s: %w", configPath, err)
	}

	return tg, nil
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

// loadZoneFile reads from a zone file the cuts, their name servers and the glue for them, and the record sets declared outside every delegation. It does not repeat the server's validation: the suite only needs to know what to expect.
func loadZoneFile(zoneFilePath string, zone string) (targetZoneFile, error) {
	file, err := os.Open(zoneFilePath)
	if err != nil {
		return targetZoneFile{}, fmt.Errorf("opening zone file: %w", err)
	}
	defer file.Close()

	zp := dns.NewZoneParser(file, zone, zoneFilePath)
	zp.SetDefaultTTL(300)
	byCut := make(map[string]*targetDelegation)
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
			// The server refuses an NS record at the apex, whose name servers come from its configuration, so it is no cut and no referral may be expected there.
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
	return targetZoneFile{delegations: delegations, recordSets: recordSets}, nil
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

func optionalEnv(env map[string]any, key string) (string, bool, error) {
	value, present := env[key]
	if !present {
		return "", false, nil
	}
	s, ok := value.(string)
	if !ok {
		return "", true, fmt.Errorf("must be a string, got %T", value)
	}
	return strings.Trim(s, asciiWhitespace), true, nil
}

func stagingRoots() ([]*x509.Certificate, error) {
	names, err := stagingRootFiles.ReadDir("testdata")
	if err != nil {
		return nil, fmt.Errorf("listing vendored staging roots: %w", err)
	}

	var roots []*x509.Certificate
	for _, entry := range names {
		name := path.Join("testdata", entry.Name())
		content, err := stagingRootFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		block, rest := pem.Decode(content)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: no PEM certificate block", name)
		}
		if len(strings.Trim(string(rest), asciiWhitespace)) != 0 {
			return nil, fmt.Errorf("%s: must contain exactly one certificate", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		roots = append(roots, cert)
	}
	return roots, nil
}

func stagingRootPool() (*x509.CertPool, error) {
	roots, err := stagingRoots()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	return pool, nil
}

func TestLoadProductionConfig(t *testing.T) {
	tg, err := loadTarget(filepath.Join("..", "fly.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if tg.app != "local-ip" {
		t.Errorf("app = %q, want %q", tg.app, "local-ip")
	}
	if tg.domain != "local-ip.sh" {
		t.Errorf("domain = %q, want %q", tg.domain, "local-ip.sh")
	}
	want := []netip.Addr{netip.MustParseAddr("137.66.40.11"), netip.MustParseAddr("137.66.40.12")}
	if !slices.Equal(tg.nameServers, want) {
		t.Errorf("nameServers = %v, want %v", tg.nameServers, want)
	}
	if tg.stagingCA {
		t.Error("stagingCA = true, want false")
	}
	if got, want := tg.soaRname(), "admin.local-ip.sh."; got != want {
		t.Errorf("soaRname = %q, want %q", got, want)
	}
	assertRecordSets(t, tg.recordSets, [][]string{
		{`local-ip.sh. 300 IN TXT "v=spf1 include:capsulecorp.dev ~all"`},
		{`local-ip.sh. 300 IN MX 10 email.capsulecorp.dev.`},
		{`autodiscover.local-ip.sh. 300 IN CNAME email.capsulecorp.dev.`},
		{`autoconfig.local-ip.sh. 300 IN CNAME email.capsulecorp.dev.`},
		{`_autodiscover._tcp.local-ip.sh. 300 IN SRV 0 0 443 email.capsulecorp.dev.`},
		{`_dmarc.local-ip.sh. 300 IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@local-ip.sh; ruf=mailto:admin@local-ip.sh"`},
		{`dkim._domainkey.local-ip.sh. 300 IN TXT "v=DKIM1;k=rsa;t=s;s=email;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMW6NFo34qzKRPbzK41GwbWncB8IDg1i2eA2VWznIVDmTzzsqILaBOGv2xokVpzZm0QRF9wSbeVUmvwEeQ7Z6wkfMjawenDEc3XxsNSvQUVBP6LU/xcm1zsR8wtD8r5J+Jm45pNFaateiM/kb/Eypp2ntdtd8CPsEgCEDpNb62LWdy0yzRdZ/M/" "fNn51UMN8hVFp4YfZngAt3bQwa6kPtgvTeqEbpNf5xanpDysNJt2S8zfqJMVGvnr8JaJiTv7ZlKMMp94aC5Ndcir1WbMyfmgSnGgemuCTVMWDGPJnXDi+8BQMH1b1hmTpWDiVdVlehyyWx5AfPrsWG9cEuDIfXwIDAQAB"`},
	})
	i := slices.IndexFunc(tg.recordSets, func(set targetRecordSet) bool { return set.owner == "dkim._domainkey.local-ip.sh." })
	if i < 0 {
		return
	}
	var lengths []int
	for _, rr := range tg.recordSets[i].records {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				lengths = append(lengths, len(s))
			}
		}
	}
	if len(tg.recordSets[i].records) != 1 || !slices.Equal(lengths, []int{255, 165}) {
		t.Errorf("DKIM record set has %d records with strings of %v octets, want one record of two strings of 255 and 165 octets", len(tg.recordSets[i].records), lengths)
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

func TestLoadStagingConfig(t *testing.T) {
	tg, err := loadTarget(filepath.Join("..", "fly.staging.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if tg.app != "local-ip-staging" {
		t.Errorf("app = %q, want %q", tg.app, "local-ip-staging")
	}
	if tg.domain != "xip-staging.local-ip.sh" {
		t.Errorf("domain = %q, want %q", tg.domain, "xip-staging.local-ip.sh")
	}
	want := []netip.Addr{netip.MustParseAddr("149.248.203.129")}
	if !slices.Equal(tg.nameServers, want) {
		t.Errorf("nameServers = %v, want %v", tg.nameServers, want)
	}
	if !tg.stagingCA {
		t.Error("stagingCA = false, want true")
	}
	if got, want := tg.soaRname(), "admin.local-ip.sh."; got != want {
		t.Errorf("soaRname = %q, want %q", got, want)
	}
	assertRecordSets(t, tg.recordSets, [][]string{
		{`e2e-records.xip-staging.local-ip.sh. 300 IN A 192.0.2.10`},
		{`e2e-records.xip-staging.local-ip.sh. 300 IN AAAA 2001:db8::10`},
		{`e2e-records.xip-staging.local-ip.sh. 300 IN TXT "local-ip.sh e2e" "second string"`},
		{`e2e-records.xip-staging.local-ip.sh. 300 IN MX 10 mail.example.net.`},
		{`e2e-records.xip-staging.local-ip.sh. 300 IN CAA 0 issue ";"`},
		{`e2e-alias.xip-staging.local-ip.sh. 600 IN CNAME target.example.net.`},
		{`_e2e._tcp.xip-staging.local-ip.sh. 300 IN SRV 0 0 443 target.example.net.`},
		{`xip-staging.local-ip.sh. 300 IN TXT "local-ip.sh test instance"`},
		stagingTXTRecords(udpTXTLabel, 4),
		stagingTXTRecords(tcpTXTLabel, 12),
	})
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

// stagingTXTRecords spells the TXT set the staging zone file declares at the label: n records, each of one string of 180 octets that starts with its position.
func stagingTXTRecords(label string, n int) []string {
	records := make([]string, n)
	for i := range n {
		prefix := fmt.Sprintf("%s record %d of %d ", label, i+1, n)
		records[i] = fmt.Sprintf(`%s.xip-staging.local-ip.sh. 300 IN TXT "%s%s"`, label, prefix, strings.Repeat("x", 180-len(prefix)))
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

func validEnv(overrides map[string]string) map[string]string {
	env := map[string]string{
		"XIP_DOMAIN":      `"example.com"`,
		"XIP_NAMESERVERS": `"1.2.3.4,5.6.7.8"`,
		"XIP_EMAIL":       `"admin@example.com"`,
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

func TestLoadTargetNormalisesValues(t *testing.T) {
	configPath := writeConfig(t, flyConfig(`"  my-app  "`, map[string]string{
		"XIP_DOMAIN":      `" Example.COM. "`,
		"XIP_NAMESERVERS": `" 1.2.3.4 ,\t5.6.7.8 "`,
		"XIP_EMAIL":       `" first.last@example.com "`,
		"XIP_STAGING":     `" true "`,
	}))

	tg, err := loadTarget(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if tg.app != "my-app" {
		t.Errorf("app = %q, want %q", tg.app, "my-app")
	}
	if tg.domain != "example.com" {
		t.Errorf("domain = %q, want %q", tg.domain, "example.com")
	}
	if tg.zone() != "example.com." {
		t.Errorf("zone = %q, want %q", tg.zone(), "example.com.")
	}
	wantHosts := []string{"ns1.example.com.", "ns2.example.com."}
	if !slices.Equal(tg.nameServerHosts(), wantHosts) {
		t.Errorf("nameServerHosts = %v, want %v", tg.nameServerHosts(), wantHosts)
	}
	wantIPs := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")}
	if !slices.Equal(tg.nameServers, wantIPs) {
		t.Errorf("nameServers = %v, want %v", tg.nameServers, wantIPs)
	}
	if tg.email != "first.last@example.com" {
		t.Errorf("email = %q, want %q", tg.email, "first.last@example.com")
	}
	if !tg.stagingCA {
		t.Error("stagingCA = false, want true")
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
		{name: "nameservers missing", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": ""}), key: "XIP_NAMESERVERS"},
		{name: "nameservers empty", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `""`}), key: "XIP_NAMESERVERS"},
		{name: "nameservers empty element", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `"1.2.3.4,"`}), key: "XIP_NAMESERVERS"},
		{name: "nameservers blank element", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `"1.2.3.4, ,5.6.7.8"`}), key: "XIP_NAMESERVERS"},
		{name: "nameservers not an IP", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `"ns1.example.com"`}), key: "XIP_NAMESERVERS"},
		{name: "nameservers IPv6", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `"1.2.3.4,2001:db8::1"`}), key: "XIP_NAMESERVERS"},
		{name: "nameservers IPv4-mapped IPv6", app: `"a"`, env: validEnv(map[string]string{"XIP_NAMESERVERS": `"::ffff:1.2.3.4"`}), key: "XIP_NAMESERVERS"},
		{name: "email missing", app: `"a"`, env: validEnv(map[string]string{"XIP_EMAIL": ""}), key: "XIP_EMAIL"},
		{name: "email empty", app: `"a"`, env: validEnv(map[string]string{"XIP_EMAIL": `""`}), key: "XIP_EMAIL"},
		{name: "email invalid", app: `"a"`, env: validEnv(map[string]string{"XIP_EMAIL": `"not-an-address"`}), key: "XIP_EMAIL"},
		{name: "email with display name", app: `"a"`, env: validEnv(map[string]string{"XIP_EMAIL": `"Admin <admin@example.com>"`}), key: "XIP_EMAIL"},
		{name: "email in angle brackets", app: `"a"`, env: validEnv(map[string]string{"XIP_EMAIL": `"<admin@example.com>"`}), key: "XIP_EMAIL"},
		{name: "staging not a boolean", app: `"a"`, env: validEnv(map[string]string{"XIP_STAGING": `"maybe"`}), key: "XIP_STAGING"},
		{name: "staging not a string", app: `"a"`, env: validEnv(map[string]string{"XIP_STAGING": `true`}), key: "XIP_STAGING"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, flyConfig(tt.app, tt.env))

			_, err := loadTarget(configPath)
			if err == nil {
				t.Fatal("loadTarget succeeded, want an error")
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

func TestEmailToRname(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{email: "admin@local-ip.sh", want: "admin.local-ip.sh."},
		{email: "first.last@example.com", want: `first\.last.example.com.`},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			if got := emailToRname(tt.email); got != tt.want {
				t.Errorf("emailToRname(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestLoadTargetSOARname(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{name: "a plain address keeps its spelling", email: "admin@local-ip.sh", want: "admin.local-ip.sh."},
		{name: "a mixed-case address is lower-cased", email: "Admin.Team@EXAMPLE.Test", want: `admin\.team.example.test.`},
		{name: "a dot in the local part is escaped", email: "first.last@example.com", want: `first\.last.example.com.`},
		{name: "an apostrophe is escaped as the library unpacks it", email: "O'Brien@example.test", want: `o\'brien.example.test.`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tg, err := loadTarget(writeConfig(t, flyConfig(`"a"`, validEnv(map[string]string{"XIP_EMAIL": strconv.Quote(tt.email)}))))
			if err != nil {
				t.Fatal(err)
			}
			if got := tg.soaRname(); got != tt.want {
				t.Errorf("soaRname() for %q = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

func TestLoadTargetRejectsEmailThatCannotBeAnRname(t *testing.T) {
	label := func(c string, n int) string { return strings.Repeat(c, n) }
	tests := []struct {
		name  string
		email string
	}{
		{name: "a local part of 64 octets is longer than a label", email: label("a", 64) + "@example.test"},
		{name: "a local part and a domain that make a name of 257 octets", email: label("a", 63) + "@" + label("b", 63) + "." + label("c", 63) + "." + label("d", 63)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, flyConfig(`"a"`, validEnv(map[string]string{"XIP_EMAIL": strconv.Quote(tt.email)})))
			_, err := loadTarget(configPath)
			if err == nil {
				t.Fatal("loadTarget succeeded, want an error")
			}
			for _, want := range []string{configPath, "XIP_EMAIL", "RNAME"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestStagingRootPool(t *testing.T) {
	wantFingerprints := map[string]string{
		"(STAGING) Pretend Pear X1":        "E7:05:70:A9:89:F8:56:5A:AB:DF:7C:AE:27:AB:D1:62:18:72:D6:A3:F8:11:E3:FE:F2:7E:3D:BA:02:91:21:98",
		"(STAGING) Bogus Broccoli X2":      "9B:2A:33:9F:E6:A3:E8:55:85:C4:CD:75:53:6C:B8:C1:CF:7C:D6:03:B9:A6:4B:EC:25:21:85:8A:E4:8D:A8:5D",
		"(STAGING) Yearning Yucca Root YE": "B5:9B:FC:0B:A5:2D:AF:84:98:53:B7:32:4A:91:E8:2F:03:1D:B3:39:7F:35:64:41:57:35:2C:DE:63:84:B5:6C",
		"(STAGING) Yonder Yam Root YR":     "EF:11:5F:B5:9E:04:0F:F3:9D:15:FD:8F:3E:F5:40:63:C7:04:32:1D:83:CB:08:12:13:27:2F:77:D3:09:16:72",
	}

	roots, err := stagingRoots()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != len(wantFingerprints) {
		t.Fatalf("got %d vendored roots, want %d", len(roots), len(wantFingerprints))
	}

	seen := make(map[string]bool, len(wantFingerprints))
	expected := x509.NewCertPool()
	for _, root := range roots {
		cn := root.Subject.CommonName
		want, ok := wantFingerprints[cn]
		if !ok {
			t.Errorf("unexpected vendored root %q", cn)
			continue
		}
		sum := sha256.Sum256(root.Raw)
		if got := colonHex(sum[:]); got != want {
			t.Errorf("root %q has fingerprint %s, want %s", cn, got, want)
			continue
		}
		if seen[cn] {
			t.Errorf("root %q is vendored more than once", cn)
		}
		seen[cn] = true
		if err := root.CheckSignatureFrom(root); err != nil {
			t.Errorf("root %q is not self-signed: %v", cn, err)
		}
		expected.AddCert(root)
	}

	for cn := range wantFingerprints {
		if !seen[cn] {
			t.Errorf("root %q is not vendored", cn)
		}
	}

	pool, err := stagingRootPool()
	if err != nil {
		t.Fatal(err)
	}
	if !pool.Equal(expected) {
		t.Error("staging trust pool does not contain exactly the vendored roots")
	}
	if pool.Equal(x509.NewCertPool()) {
		t.Error("staging trust pool is empty")
	}
}

func colonHex(b []byte) string {
	encoded := strings.ToUpper(hex.EncodeToString(b))
	pairs := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		pairs = append(pairs, encoded[i:i+2])
	}
	return strings.Join(pairs, ":")
}

func TestLoadTargetDelegations(t *testing.T) {
	tests := []struct {
		configPath string
		want       []targetDelegation
	}{
		{
			configPath: filepath.Join("..", "fly.toml"),
			want: []targetDelegation{{
				cut:         "xip-staging.local-ip.sh.",
				nameServers: []string{"ns1.xip-staging.local-ip.sh."},
				glue:        map[string][]netip.Addr{"ns1.xip-staging.local-ip.sh.": {netip.MustParseAddr("149.248.203.129")}},
			}},
		},
		{
			configPath: filepath.Join("..", "fly.staging.toml"),
			want: []targetDelegation{{
				cut:         "e2e-delegated.xip-staging.local-ip.sh.",
				nameServers: []string{"ns1.e2e-delegated.xip-staging.local-ip.sh."},
				glue:        map[string][]netip.Addr{"ns1.e2e-delegated.xip-staging.local-ip.sh.": {netip.MustParseAddr("192.0.2.53")}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.configPath, func(t *testing.T) {
			tg, err := loadTarget(tt.configPath)
			if err != nil {
				t.Fatal(err)
			}
			assertDelegations(t, tg.delegations, tt.want)
			if len(tg.recordSets) == 0 {
				t.Error("no record sets loaded, want the records the zone file declares besides its delegations")
			}
			for _, set := range tg.recordSets {
				for _, d := range tg.delegations {
					if dns.IsSubDomain(d.cut, set.owner) {
						t.Errorf("record set %s %s is at or below the cut %s, want only glue there", set.owner, dns.Type(set.rrtype), d.cut)
					}
				}
			}
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

	const zoneFileEntry = "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n"

	tests := []struct {
		name     string
		zoneEnv  string
		files    string
		zone     string
		want     []targetDelegation
		wantSets [][]string
		wantErr  []string
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
			name:    "an NS record at the apex is neither a cut nor a record set",
			zoneEnv: zoneFile,
			files:   zoneFileEntry,
			zone:    "@ NS ns.other.test.\n@ TXT \"apex\"\n",
			wantSets: [][]string{
				{`example.com. 300 IN TXT "apex"`},
			},
		},
		{
			name: "no XIP_ZONE_FILE yields no delegations",
		},
		{
			name:    "empty XIP_ZONE_FILE yields no delegations",
			zoneEnv: `""`,
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
			wantErr: []string{"env.XIP_ZONE_FILE", "[[files]]", "guest_path", "local_path"},
		},
		{
			name:    "no [[files]] entry with the guest path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/other.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    validZone,
			wantErr: []string{"env.XIP_ZONE_FILE", "[[files]]", "guest_path", "local_path"},
		},
		{
			name:    "two [[files]] entries with the guest path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n",
			zone:    validZone,
			wantErr: []string{"env.XIP_ZONE_FILE", "[[files]]", "found 2"},
		},
		{
			name:    "empty local path",
			zoneEnv: zoneFile,
			files:   "[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"  \"\n",
			wantErr: []string{"env.XIP_ZONE_FILE", "[[files]]", "local_path"},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv(nil)
			if tt.zoneEnv != "" {
				env["XIP_ZONE_FILE"] = tt.zoneEnv
			}
			configPath := writeConfig(t, flyConfig(`"a"`, env)+"\n"+tt.files)
			if tt.zone != "" {
				zonesDir := filepath.Join(filepath.Dir(configPath), "zones")
				if err := os.Mkdir(zonesDir, 0o700); err != nil {
					t.Fatal(err)
				}
				writeZoneFile(t, zonesDir, "test.zone", tt.zone)
			}

			tg, err := loadTarget(configPath)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("loadTarget succeeded, want an error")
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
			assertRecordSets(t, tg.recordSets, tt.wantSets)
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
			env := validEnv(nil)
			env["XIP_ZONE_FILE"] = `"/etc/local-ip.zone"`
			configPath := writeConfig(t, flyConfig(`"a"`, env)+"\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"zones/test.zone\"\n")
			zonesDir := filepath.Join(filepath.Dir(configPath), "zones")
			if err := os.Mkdir(zonesDir, 0o700); err != nil {
				t.Fatal(err)
			}
			writeZoneFile(t, zonesDir, "test.zone", tt.zone+"\n")

			tg, err := loadTarget(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(tg.recordSets) != 1 || len(tg.recordSets[0].records) != 1 || tg.recordSets[0].rrtype != tt.rrtype {
				t.Fatalf("record sets = %+v, want one set of one %s record", tg.recordSets, dns.Type(tt.rrtype))
			}
			set := tg.recordSets[0]
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

// TestDelegationsMatchTargets keeps the two Fly configs consistent: when one target's zone lies
// inside the other's, the parent must delegate it to exactly the child's name servers, or the
// child cannot be found through public DNS and cannot obtain certificates.
func TestDelegationsMatchTargets(t *testing.T) {
	var targets []*target
	for _, configPath := range []string{filepath.Join("..", "fly.toml"), filepath.Join("..", "fly.staging.toml")} {
		tg, err := loadTarget(configPath)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, tg)
	}

	checked := 0
	for _, parent := range targets {
		for _, child := range targets {
			if parent == child || parent.zone() == child.zone() || !dns.IsSubDomain(parent.zone(), child.zone()) {
				continue
			}
			checked++
			i := slices.IndexFunc(parent.delegations, func(d targetDelegation) bool { return d.cut == child.zone() })
			if i < 0 {
				t.Errorf("%s does not delegate %s to %s", parent.app, child.zone(), child.app)
				continue
			}
			d := parent.delegations[i]

			wantHosts := slices.Sorted(slices.Values(child.nameServerHosts()))
			if got := slices.Sorted(slices.Values(d.nameServers)); !slices.Equal(got, wantHosts) {
				t.Errorf("%s delegates %s to %v, want %v (the name servers of %s)", parent.app, d.cut, got, wantHosts, child.app)
			}
			for j, host := range child.nameServerHosts() {
				if got, want := d.glue[host], []netip.Addr{child.nameServers[j]}; !slices.Equal(got, want) {
					t.Errorf("%s glue for %s = %v, want %v", parent.app, host, got, want)
				}
			}
		}
	}
	if checked == 0 {
		t.Error("no target's zone lies inside another's; expected production to be the parent of staging")
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
			env := validEnv(map[string]string{"XIP_ZONE_FILE": `"/etc/local-ip.zone"`})
			configPath := writeConfig(t, flyConfig(`"a"`, env)+"\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"test.zone\"\n")
			writeZoneFile(t, filepath.Dir(configPath), "test.zone", tt.zone)

			_, err := loadTarget(configPath)
			if err == nil {
				t.Fatal("loadTarget succeeded, want an error")
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
			env := validEnv(map[string]string{"XIP_ZONE_FILE": `"/etc/local-ip.zone"`})
			configPath := writeConfig(t, flyConfig(`"a"`, env)+"\n[[files]]\nguest_path = \"/etc/local-ip.zone\"\nlocal_path = \"test.zone\"\n")
			writeZoneFile(t, filepath.Dir(configPath), "test.zone", tt.zone)

			_, err := loadTarget(configPath)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("loadTarget refused the zone file: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("loadTarget succeeded, want an error")
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
