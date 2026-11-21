package app_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"local-ip.sh/app"
	"local-ip.sh/internal/acmetest"
)

const (
	testDomain = "app.test"
	// issueWithin bounds the wait for both certificates; with a validation delay of a millisecond an order takes a fraction of it.
	issueWithin = 30 * time.Second
	// stopWithin bounds Run's return after cancellation, which the components promise within a few seconds.
	stopWithin = 10 * time.Second
	// dnsTimeout is how long one query has to be answered.
	dnsTimeout = 5 * time.Second
)

func TestMain(m *testing.M) {
	acmetest.Init()
	os.Exit(m.Run())
}

// logBuffer collects the JSON lines of the app's logger.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *logBuffer) entries(t *testing.T) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for line := range strings.SplitSeq(b.String(), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func (b *logBuffer) errorLines(t *testing.T) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, entry := range b.entries(t) {
		switch entry["level"] {
		case "error", "fatal", "panic":
			lines = append(lines, entry)
		}
	}
	return lines
}

func (b *logBuffer) withMessage(t *testing.T, message string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, entry := range b.entries(t) {
		if entry["message"] == message {
			lines = append(lines, entry)
		}
	}
	return lines
}

func newConfig(t *testing.T, logs *logBuffer) app.Config {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log of the app:\n%s", logs)
		}
	})
	return app.Config{
		Domain:          testDomain,
		Email:           "admin@" + testDomain,
		NameServers:     []string{"192.0.2.53"},
		DNSAddress:      "127.0.0.1:0",
		HTTPAddress:     "127.0.0.1:0",
		HTTPSAddress:    "127.0.0.1:0",
		StateDir:        t.TempDir(),
		StaticDir:       "../http/static",
		DirectoryURL:    "https://127.0.0.1:1/dir",
		ACMEProfile:     "default",
		ValidationDelay: time.Millisecond,
		Logger:          zerolog.New(logs).Level(zerolog.InfoLevel).With().Timestamp().Logger(),
	}
}

// withAuthority points cfg at a new authority that validates through the app's own DNS server; the returned function must be called with the app once it is built.
func withAuthority(t *testing.T, cfg *app.Config) (*acmetest.CA, func(*app.App)) {
	t.Helper()
	forwarder := acmetest.NewForwarder(t)
	ca := acmetest.Start(t, forwarder.Address, time.Hour)
	cfg.DirectoryURL = ca.DirectoryURL
	cfg.TrustedRoots = ca.APIRoots
	return ca, func(a *app.App) { forwarder.SetTarget(a.DNSAddr().String()) }
}

type running struct {
	*app.App
	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
}

// start builds the app, calls connect with it before Run (connect may be nil) and runs it. At the end of the test it is stopped, and Run must have returned nil.
func start(t *testing.T, cfg app.Config, connect func(*app.App)) *running {
	t.Helper()
	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if connect != nil {
		connect(a)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{App: a, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- a.Run(ctx) }()
	t.Cleanup(func() { r.stop(t) })
	return r
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.stopOnce.Do(func() {
		r.cancel()
		select {
		case err := <-r.done:
			if err != nil {
				t.Errorf("Run returned %v, want nil", err)
			}
		case <-time.After(stopWithin):
			t.Errorf("Run did not return within %v of the cancellation", stopWithin)
		}
	})
}

func (r *running) requireRunning(t *testing.T) {
	t.Helper()
	select {
	case err := <-r.done:
		t.Fatalf("Run returned %v while nobody asked it to stop", err)
	default:
	}
}

func query(name string, qtype uint16, server string) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: dnsTimeout}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	answer, _, err := client.Exchange(message, server)
	return answer, err
}

// checkAddressAnswer fails the test unless 10-0-0-1.app.test A is answered with 10.0.0.1.
func checkAddressAnswer(t *testing.T, a *app.App) {
	t.Helper()
	if err := addressAnswer(a.DNSAddr().String()); err != nil {
		t.Fatal(err)
	}
}

func addressAnswer(server string) error {
	answer, err := query("10-0-0-1."+testDomain, dns.TypeA, server)
	if err != nil {
		return fmt.Errorf("querying 10-0-0-1.%s A: %w", testDomain, err)
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		return fmt.Errorf("10-0-0-1.%s A: rcode %s with %d answers, want one", testDomain, dns.RcodeToString[answer.Rcode], len(answer.Answer))
	}
	record, ok := answer.Answer[0].(*dns.A)
	if !ok || !record.A.Equal(net.IPv4(10, 0, 0, 1)) {
		return fmt.Errorf("10-0-0-1.%s A answered %v, want 10.0.0.1", testDomain, answer.Answer[0])
	}
	return nil
}

// httpsClient connects every request to the app's HTTPS port and verifies the server as app.test against roots.
func httpsClient(a *app.App, roots *x509.CertPool) *http.Client {
	address := a.HTTPSAddr().String()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
			TLSClientConfig: &tls.Config{ServerName: testDomain, RootCAs: roots},
			MaxConnsPerHost: 1,
		},
	}
}

func plainClient(a *app.App) *http.Client {
	address := a.HTTPAddr().String()
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type fetched struct {
	status int
	header http.Header
	body   []byte
	tls    *tls.ConnectionState
}

func get(client *http.Client, url string) (fetched, error) {
	response, err := client.Get(url)
	if err != nil {
		return fetched{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fetched{}, err
	}
	return fetched{status: response.StatusCode, header: response.Header, body: body, tls: response.TLS}, nil
}

// served is what the app serves over HTTPS at one moment: the website's leaf and the published pair.
type served struct {
	siteLeaf *x509.Certificate
	pairPEM  []byte
	keyPEM   []byte
	pair     tls.Certificate
	chain    []*x509.Certificate
}

// fetchServed asks for /, /server.pem and /server.key over HTTPS with one client, and fails when any of them is not 200.
func fetchServed(a *app.App, roots *x509.CertPool) (served, error) {
	client := httpsClient(a, roots)
	defer client.CloseIdleConnections()
	index, err := get(client, "https://"+testDomain+"/")
	if err != nil {
		return served{}, err
	}
	if index.status != http.StatusOK {
		return served{}, fmt.Errorf("HTTPS GET /: status %d", index.status)
	}
	certificate, err := get(client, "https://"+testDomain+"/server.pem")
	if err != nil {
		return served{}, err
	}
	key, err := get(client, "https://"+testDomain+"/server.key")
	if err != nil {
		return served{}, err
	}
	if certificate.status != http.StatusOK || key.status != http.StatusOK {
		return served{}, fmt.Errorf("HTTPS GET /server.pem and /server.key: status %d and %d", certificate.status, key.status)
	}
	pair, err := tls.X509KeyPair(certificate.body, key.body)
	if err != nil {
		return served{}, fmt.Errorf("loading the published pair: %w", err)
	}
	chain, err := parseChain(certificate.body)
	if err != nil {
		return served{}, err
	}
	return served{siteLeaf: index.tls.PeerCertificates[0], pairPEM: certificate.body, keyPEM: key.body, pair: pair, chain: chain}, nil
}

func parseChain(chainPEM []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing the published chain: %w", err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("the published chain holds no certificate")
	}
	return chain, nil
}

func verifyFor(t *testing.T, chain []*x509.Certificate, name string, roots *x509.CertPool) {
	t.Helper()
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates}); err != nil {
		t.Errorf("the chain does not verify for %s: %v", name, err)
	}
}

// waitForServed polls until the website and the published pair are both served over HTTPS, and until accept holds for what is served.
func waitForServed(t *testing.T, a *app.App, roots *x509.CertPool, what string, accept func(served) bool) served {
	t.Helper()
	deadline := time.Now().Add(issueWithin)
	var last error
	for {
		current, err := fetchServed(a, roots)
		if err == nil && accept(current) {
			return current
		}
		if err == nil {
			err = fmt.Errorf("not yet")
		}
		last = err
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %v; last attempt: %v", what, issueWithin, last)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func checkHandshakeFails(t *testing.T, a *app.App) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", a.HTTPSAddr().String(), &tls.Config{ServerName: testDomain, InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Error("an HTTPS handshake succeeded without a certificate")
	}
}

func TestFirstStartToRenewal(t *testing.T) {
	logs := &logBuffer{}
	cfg := newConfig(t, logs)
	cfg.Domain = "App.Test."
	ca, connect := withAuthority(t, &cfg)
	r := start(t, cfg, connect)

	// DNS does not wait for the certificates.
	checkAddressAnswer(t, r.App)

	first := waitForServed(t, r.App, ca.IssuerRoots, "serving both certificates", func(served) bool { return true })
	if leaf := first.chain[0]; !slices.Equal(leaf.DNSNames, []string{"*." + testDomain}) {
		t.Errorf("the published leaf names %v, want [*.%s]", leaf.DNSNames, testDomain)
	}
	verifyFor(t, first.chain, "x."+testDomain, ca.IssuerRoots)
	if first.siteLeaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(first.chain[0].PublicKey) {
		t.Error("the website's certificate has the published key")
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+testDomain+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := plainClient(r.App).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	_, httpsPort, _ := net.SplitHostPort(r.HTTPSAddr().String())
	if want := "https://" + testDomain + ":" + httpsPort + "/"; response.StatusCode != http.StatusMovedPermanently || response.Header.Get("Location") != want {
		t.Errorf("plain HTTP GET /: status %d to %q, want 301 to %q", response.StatusCode, response.Header.Get("Location"), want)
	}

	checkStateDirectory(t, cfg.StateDir)

	challenge, err := query("_acme-challenge."+testDomain, dns.TypeTXT, r.DNSAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Rcode != dns.RcodeSuccess || len(challenge.Answer) != 0 || len(challenge.Ns) != 1 {
		t.Errorf("_acme-challenge TXT: rcode %s, %d answers, %d authority records; want NOERROR, none, one SOA", dns.RcodeToString[challenge.Rcode], len(challenge.Answer), len(challenge.Ns))
	} else if soa, ok := challenge.Ns[0].(*dns.SOA); !ok || soa.Hdr.Ttl != 0 {
		t.Errorf("_acme-challenge TXT authority: %v, want an SOA with TTL 0", challenge.Ns[0])
	}

	probes := startProber(r.DNSAddr().String())
	r.RenewCertificates()
	renewed := waitForServed(t, r.App, ca.IssuerRoots, "renewing both certificates", func(s served) bool {
		return !sameSerial(s.siteLeaf, first.siteLeaf) && !sameSerial(s.chain[0], first.chain[0])
	})
	sent, failures := probes.stop()
	// The website's chain was verified against ca.IssuerRoots by the TLS client that fetched it.
	verifyFor(t, renewed.chain, "x."+testDomain, ca.IssuerRoots)
	if sent == 0 {
		t.Error("the prober sent no query")
	}
	if len(failures) != 0 {
		t.Errorf("%d of %d probes failed during the renewal, the first: %v", len(failures), sent, failures[0])
	}
}

func sameSerial(a, b *x509.Certificate) bool {
	return a.SerialNumber.Cmp(b.SerialNumber) == 0
}

func checkStateDirectory(t *testing.T, stateDir string) {
	t.Helper()
	var files []string
	err := filepath.WalkDir(stateDir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(stateDir, name)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		if runtime.GOOS != "windows" {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("%s has mode %v, want 0600", relative, mode)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	if len(files) != 3 {
		t.Fatalf("the state directory holds %v, want account.pem, %[2]s/site.pem and %[2]s/wildcard.pem under one authority directory", files, testDomain)
	}
	authority, _, _ := strings.Cut(files[0], "/")
	want := []string{authority + "/account.pem", authority + "/" + testDomain + "/site.pem", authority + "/" + testDomain + "/wildcard.pem"}
	if authority == "" || !slices.Equal(files, want) {
		t.Errorf("the state directory holds %v, want %v", files, want)
	}
}

type prober struct {
	cancel   context.CancelFunc
	finished chan struct{}
	sent     atomic.Int64
	mu       sync.Mutex
	failures []error
}

// startProber asks for 10-0-0-1.app.test A every 10 milliseconds until it is stopped.
func startProber(server string) *prober {
	ctx, cancel := context.WithCancel(context.Background())
	p := &prober{cancel: cancel, finished: make(chan struct{})}
	go func() {
		defer close(p.finished)
		for ctx.Err() == nil {
			p.sent.Add(1)
			if err := addressAnswer(server); err != nil {
				p.mu.Lock()
				p.failures = append(p.failures, err)
				p.mu.Unlock()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return p
}

func (p *prober) stop() (sent int64, failures []error) {
	p.cancel()
	<-p.finished
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent.Load(), slices.Clone(p.failures)
}

func TestRestartWithoutCertificateAuthority(t *testing.T) {
	logs := &logBuffer{}
	cfg := newConfig(t, logs)
	ca, connect := withAuthority(t, &cfg)
	first := start(t, cfg, connect)
	before := waitForServed(t, first.App, ca.IssuerRoots, "serving both certificates", func(served) bool { return true })
	first.stop(t)
	ca.Stop()

	restartLogs := &logBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log of the restarted app:\n%s", restartLogs)
		}
	})
	cfg.Logger = zerolog.New(restartLogs).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	second := start(t, cfg, nil)

	// One attempt and no polling: the stored certificates are served from the first handshake on.
	after, err := fetchServed(second.App, ca.IssuerRoots)
	if err != nil {
		t.Fatalf("the restarted app does not serve its stored certificates at once: %v", err)
	}
	if !sameSerial(after.siteLeaf, before.siteLeaf) {
		t.Errorf("the website's serial number is %v after the restart, want %v", after.siteLeaf.SerialNumber, before.siteLeaf.SerialNumber)
	}
	if !sameSerial(after.chain[0], before.chain[0]) {
		t.Errorf("the published serial number is %v after the restart, want %v", after.chain[0].SerialNumber, before.chain[0].SerialNumber)
	}
	checkAddressAnswer(t, second.App)

	select {
	case err := <-second.done:
		t.Fatalf("Run returned %v without being asked to stop", err)
	case <-time.After(2 * time.Second):
	}
	if lines := restartLogs.errorLines(t); len(lines) != 0 {
		t.Errorf("error lines without an authority: %v", lines)
	}
}

func TestCertificateFailuresDoNotStopDNS(t *testing.T) {
	logs := &logBuffer{}
	cfg := newConfig(t, logs)
	wrongDNS := acmetest.ServeTXT(t, func(string) []string { return []string{"not the challenge value"} })
	ca := acmetest.Start(t, wrongDNS, time.Hour)
	cfg.DirectoryURL = ca.DirectoryURL
	cfg.TrustedRoots = ca.APIRoots
	r := start(t, cfg, nil)

	checkAddressAnswer(t, r.App)
	failed := waitForOrderFailure(t, logs)
	if failed["problem_type"] == nil {
		t.Errorf("the failure has no problem_type: %v", failed)
	}
	checkServingWithoutCertificates(t, r)
}

func TestUnreachableCertificateAuthority(t *testing.T) {
	logs := &logBuffer{}
	cfg := newConfig(t, logs)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := listener.Addr().String()
	listener.Close()
	cfg.DirectoryURL = "https://" + refused + "/dir"
	r := start(t, cfg, nil)

	checkAddressAnswer(t, r.App)
	failed := waitForOrderFailure(t, logs)
	if failed["problem_type"] != nil {
		t.Errorf("a refused connection was logged with a problem_type: %v", failed)
	}
	checkServingWithoutCertificates(t, r)
}

func waitForOrderFailure(t *testing.T, logs *logBuffer) map[string]any {
	t.Helper()
	deadline := time.Now().Add(issueWithin)
	for {
		if lines := logs.withMessage(t, "Certificate order failed"); len(lines) > 0 {
			return lines[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Certificate order failed line within %v", issueWithin)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func checkServingWithoutCertificates(t *testing.T, r *running) {
	t.Helper()
	checkAddressAnswer(t, r.App)
	client := plainClient(r.App)
	index, err := get(client, "http://"+testDomain+"/")
	if err != nil {
		t.Fatal(err)
	}
	if index.status != http.StatusOK {
		t.Errorf("plain HTTP GET /: status %d, want 200", index.status)
	}
	pair, err := get(client, "http://"+testDomain+"/server.pem")
	if err != nil {
		t.Fatal(err)
	}
	if pair.status != http.StatusServiceUnavailable {
		t.Errorf("plain HTTP GET /server.pem: status %d, want 503", pair.status)
	}
	checkHandshakeFails(t, r.App)
	r.requireRunning(t)
}

func TestNewReportsBindErrors(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	for _, test := range []struct {
		name string
		set  func(*app.Config)
		want string
	}{
		{name: "HTTP", set: func(cfg *app.Config) { cfg.HTTPAddress = held.Addr().String() }, want: "listening for HTTP on"},
		{name: "HTTPS", set: func(cfg *app.Config) { cfg.HTTPSAddress = held.Addr().String() }, want: "listening for HTTPS on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := newConfig(t, &logBuffer{})
			test.set(&cfg)
			_, err := app.New(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("New returned %v, want an error containing %q", err, test.want)
			}
		})
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*app.Config)
		want string
	}{
		{name: "empty domain", set: func(cfg *app.Config) { cfg.Domain = "" }, want: "invalid domain"},
		{name: "domain made of dots", set: func(cfg *app.Config) { cfg.Domain = ".." }, want: "invalid domain"},
		{name: "email with a display name", set: func(cfg *app.Config) { cfg.Email = "Admin <admin@app.test>" }, want: "DNS server:"},
		{name: "name server that is not IPv4", set: func(cfg *app.Config) { cfg.NameServers = []string{"::1"} }, want: "DNS server:"},
		{name: "missing zone file", set: func(cfg *app.Config) { cfg.ZoneFile = filepath.Join(t.TempDir(), "missing.zone") }, want: "DNS server:"},
		{name: "empty state directory", set: func(cfg *app.Config) { cfg.StateDir = "" }, want: "certificates:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := newConfig(t, &logBuffer{})
			test.set(&cfg)
			_, err := app.New(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("New returned %v, want an error containing %q", err, test.want)
			}
		})
	}
}
