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

func (tg *target) soaRname() string {
	return emailToRname(tg.email)
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
		App any            `toml:"app"`
		Env map[string]any `toml:"env"`
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

	return tg, nil
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
}

func TestLoadStagingConfig(t *testing.T) {
	tg, err := loadTarget(filepath.Join("..", "fly.staging.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if tg.app != "local-ip-staging" {
		t.Errorf("app = %q, want %q", tg.app, "local-ip-staging")
	}
	if tg.domain != "staging.local-ip.sh" {
		t.Errorf("domain = %q, want %q", tg.domain, "staging.local-ip.sh")
	}
	want := []netip.Addr{netip.MustParseAddr("149.248.203.129")}
	if !slices.Equal(tg.nameServers, want) {
		t.Errorf("nameServers = %v, want %v", tg.nameServers, want)
	}
	if !tg.stagingCA {
		t.Error("stagingCA = false, want true")
	}
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
