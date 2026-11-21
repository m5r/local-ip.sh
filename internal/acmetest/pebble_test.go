package acmetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/miekg/dns"
)

func TestMain(m *testing.M) {
	// This stands for a developer's shell that exports it: Init must override it, or every issuance would succeed without a DNS lookup and TestUnservedValueIsRefused would catch that.
	if err := os.Setenv("PEBBLE_VA_ALWAYS_VALID", "1"); err != nil {
		panic(err)
	}
	Init()
	// Since Go 1.15 the test binary exits with the result of m.Run when TestMain returns.
	m.Run()
}

const (
	testDomain    = "example.com"
	challengeName = "_acme-challenge.example.com"
	shortValidity = 2 * time.Hour
)

// records is an in-memory DNS-01 solver whose values the DNS side of a test serves; it counts the lookups so that a test can tell that validation went through it.
type records struct {
	mu      sync.Mutex
	values  map[string][]string
	lookups map[string]int
}

func newRecords() *records {
	return &records{values: map[string][]string{}, lookups: map[string]int{}}
}

func (r *records) Present(_ context.Context, chal acme.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := chal.DNS01TXTRecordName()
	r.values[name] = append(r.values[name], chal.DNS01KeyAuthorization())
	return nil
}

func (r *records) CleanUp(_ context.Context, chal acme.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := chal.DNS01TXTRecordName()
	if i := slices.Index(r.values[name], chal.DNS01KeyAuthorization()); i >= 0 {
		r.values[name] = slices.Delete(r.values[name], i, i+1)
	}
	return nil
}

func (r *records) lookup(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups[name]++
	return slices.Clone(r.values[name])
}

func (r *records) lookupCount(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups[name]
}

func (r *records) published(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.values[name])
}

func newHTTPClient(t *testing.T, roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func newClient(t *testing.T, ca *CA, solver acmez.Solver) *acmez.Client {
	return &acmez.Client{
		Client: &acme.Client{
			Directory:  ca.DirectoryURL,
			HTTPClient: newHTTPClient(t, ca.APIRoots),
			UserAgent:  "acmetest-test",
		},
		ChallengeSolvers: map[string]acmez.Solver{acme.ChallengeTypeDNS01: solver},
	}
}

// testContext bounds every exchange with the authority so that a hang fails the test instead of blocking the run.
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newAccount(t *testing.T, ctx context.Context, client *acmez.Client) acme.Account {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	account, err := client.NewAccount(ctx, acme.Account{TermsOfServiceAgreed: true, PrivateKey: key})
	if err != nil {
		t.Fatalf("registering an account: %v", err)
	}
	return account
}

func orderParameters(t *testing.T, account acme.Account, profile, name string) acmez.OrderParameters {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		t.Fatal(err)
	}
	params.Profile = profile
	return params
}

func obtain(t *testing.T, ctx context.Context, client *acmez.Client, account acme.Account, profile, name string) []*x509.Certificate {
	t.Helper()
	chains, err := client.ObtainCertificate(ctx, orderParameters(t, account, profile, name))
	if err != nil {
		t.Fatalf("obtaining a certificate for %s with profile %q: %v", name, profile, err)
	}
	return parseChain(t, chains[0].ChainPEM)
}

func parseChain(t *testing.T, chainPEM []byte) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing the chain: %v", err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) < 2 {
		t.Fatalf("chain has %d certificates, want a leaf and at least one intermediate", len(chain))
	}
	return chain
}

func verifyChain(chain []*x509.Certificate, name string, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates})
	return err
}

func assertVerifies(t *testing.T, chain []*x509.Certificate, name string, roots *x509.CertPool) {
	t.Helper()
	if err := verifyChain(chain, name, roots); err != nil {
		t.Errorf("chain for %s does not verify: %v", name, err)
	}
}

func assertLifetime(t *testing.T, leaf *x509.Certificate, want time.Duration) {
	t.Helper()
	// Pebble's NotAfter is the last second of validity, inclusive.
	if got := leaf.NotAfter.Sub(leaf.NotBefore) + time.Second; got != want {
		t.Errorf("lifetime of %v = %v, want %v", leaf.DNSNames, got, want)
	}
}

func TestIssueWithServeTXT(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	ca := Start(t, ServeTXT(t, recs.lookup), shortValidity)
	client := newClient(t, ca, recs)
	account := newAccount(t, ctx, client)

	site := obtain(t, ctx, client, account, "default", testDomain)
	if recs.lookupCount(challengeName) == 0 {
		t.Errorf("the first order of a new account asked nothing at %s", challengeName)
	}
	assertVerifies(t, site, testDomain, ca.IssuerRoots)
	if !slices.Equal(site[0].DNSNames, []string{testDomain}) {
		t.Errorf("site names = %v", site[0].DNSNames)
	}
	assertLifetime(t, site[0], 90*24*time.Hour)

	wildcard := obtain(t, ctx, client, account, "default", "*."+testDomain)
	assertVerifies(t, wildcard, "anything."+testDomain, ca.IssuerRoots)
	if !slices.Equal(wildcard[0].DNSNames, []string{"*." + testDomain}) {
		t.Errorf("wildcard names = %v", wildcard[0].DNSNames)
	}

	short := obtain(t, ctx, client, account, "short", testDomain)
	assertVerifies(t, short, testDomain, ca.IssuerRoots)
	assertLifetime(t, short[0], shortValidity)

	if left := recs.published(challengeName); len(left) != 0 {
		t.Errorf("values still published after the orders: %v", left)
	}
}

func TestUnservedValueIsRefused(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	served := newRecords()
	ca := Start(t, ServeTXT(t, served.lookup), shortValidity)
	client := newClient(t, ca, recs)
	account := newAccount(t, ctx, client)

	_, err := client.ObtainCertificate(ctx, orderParameters(t, account, "default", testDomain))
	var problem acme.Problem
	if !errors.As(err, &problem) || problem.Type != acme.ProblemTypeUnauthorized {
		t.Fatalf("ordering with a value that is never served: err = %v, want an unauthorized problem", err)
	}
	if served.lookupCount(challengeName) == 0 {
		t.Errorf("the refusal came without a lookup at %s", challengeName)
	}
}

func TestOffersExactlyTwoProfiles(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	ca := Start(t, ServeTXT(t, recs.lookup), shortValidity)
	client := newClient(t, ca, recs)

	directory, err := client.GetDirectory(ctx)
	if err != nil {
		t.Fatalf("fetching the directory: %v", err)
	}
	var offered []string
	for name := range directory.Meta.Profiles {
		offered = append(offered, name)
	}
	slices.Sort(offered)
	if !slices.Equal(offered, []string{"default", "short"}) {
		t.Errorf("profiles = %v, want [default short]", offered)
	}

	account := newAccount(t, ctx, client)
	_, err = client.ObtainCertificate(ctx, orderParameters(t, account, "unknown", testDomain))
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("ordering with an unknown profile: err = %v, want an error that names it", err)
	}
}

func TestServeTXTAnswers(t *testing.T) {
	address := ServeTXT(t, func(name string) []string {
		if name == challengeName {
			return []string{"one", strings.Repeat("x", 300)}
		}
		return nil
	})
	client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}

	query := new(dns.Msg).SetQuestion("_ACME-Challenge.Example.com.", dns.TypeTXT)
	answer, _, err := client.Exchange(query, address)
	if err != nil {
		t.Fatalf("querying %s: %v", address, err)
	}
	if answer.Rcode != dns.RcodeSuccess || !answer.Authoritative || len(answer.Answer) != 2 {
		t.Fatalf("answer = %v", answer)
	}
	var values []string
	for _, rr := range answer.Answer {
		txt := rr.(*dns.TXT)
		if txt.Hdr.Ttl != 0 {
			t.Errorf("TTL = %d, want 0", txt.Hdr.Ttl)
		}
		values = append(values, strings.Join(txt.Txt, ""))
	}
	if !slices.Equal(values, []string{"one", strings.Repeat("x", 300)}) {
		t.Errorf("values = %q", values)
	}

	query = new(dns.Msg).SetQuestion(challengeName+".", dns.TypeA)
	answer, _, err = client.Exchange(query, address)
	if err != nil {
		t.Fatalf("querying %s: %v", address, err)
	}
	if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
		t.Errorf("A query answer = %v, want an empty NOERROR", answer)
	}
}

// serveUDP stands for the server under test, which listens on UDP only.
func serveUDP(t *testing.T, lookup func(name string) []string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		answer := new(dns.Msg).SetReply(query)
		question := query.Question[0]
		if question.Qtype == dns.TypeTXT {
			for _, value := range lookup(strings.TrimSuffix(question.Name, ".")) {
				answer.Answer = append(answer.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{value}})
			}
		}
		_ = w.WriteMsg(answer)
	})}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("serving DNS over UDP: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Shutdown()
		<-done
	})
	return conn.LocalAddr().String()
}

func TestIssueThroughForwarder(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	forwarder := NewForwarder(t)

	tcp := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
	answer, _, err := tcp.Exchange(new(dns.Msg).SetQuestion(challengeName+".", dns.TypeTXT), forwarder.Address)
	if err != nil {
		t.Fatalf("querying the forwarder before its target is set: %v", err)
	}
	if answer.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode before SetTarget = %s, want SERVFAIL", dns.RcodeToString[answer.Rcode])
	}

	ca := Start(t, forwarder.Address, shortValidity)
	forwarder.SetTarget(serveUDP(t, recs.lookup))

	client := newClient(t, ca, recs)
	account := newAccount(t, ctx, client)
	chain := obtain(t, ctx, client, account, "default", testDomain)
	assertVerifies(t, chain, testDomain, ca.IssuerRoots)
	if recs.lookupCount(challengeName) == 0 {
		t.Errorf("the UDP server saw no lookup at %s", challengeName)
	}
}

func TestForgetStartsAnEmptyAuthority(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	ca := Start(t, ServeTXT(t, recs.lookup), shortValidity)
	directoryURL := ca.DirectoryURL
	client := newClient(t, ca, recs)
	account := newAccount(t, ctx, client)
	before := obtain(t, ctx, client, account, "default", testDomain)
	oldRoots := ca.IssuerRoots.Clone()

	ca.Forget()

	if ca.DirectoryURL != directoryURL {
		t.Errorf("DirectoryURL changed from %s to %s", directoryURL, ca.DirectoryURL)
	}
	_, err := client.ObtainCertificate(ctx, orderParameters(t, account, "default", testDomain))
	var problem acme.Problem
	if !errors.As(err, &problem) || problem.Type != acme.ProblemTypeAccountDoesNotExist {
		t.Fatalf("ordering with an account of the forgotten server: err = %v, want an accountDoesNotExist problem", err)
	}

	again, err := client.NewAccount(ctx, acme.Account{TermsOfServiceAgreed: true, PrivateKey: account.PrivateKey})
	if err != nil {
		t.Fatalf("registering the same key again: %v", err)
	}
	if again.Location == account.Location {
		t.Errorf("the new server gave the same account URL %s", again.Location)
	}

	after := obtain(t, ctx, client, again, "default", testDomain)
	assertVerifies(t, before, testDomain, ca.IssuerRoots)
	assertVerifies(t, after, testDomain, ca.IssuerRoots)
	if err := verifyChain(after, testDomain, oldRoots); err == nil {
		t.Error("a certificate of the new server verifies against the old roots: it did not issue from new keys")
	}
}

func TestStopRefusesConnections(t *testing.T) {
	recs := newRecords()
	ca := Start(t, ServeTXT(t, recs.lookup), shortValidity)
	httpClient := newHTTPClient(t, ca.APIRoots)

	response, err := httpClient.Get(ca.DirectoryURL)
	if err != nil {
		t.Fatalf("fetching the directory: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("directory status = %d", response.StatusCode)
	}

	ca.Stop()

	request, err := http.NewRequest(http.MethodGet, ca.DirectoryURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	host := request.URL.Host
	if conn, err := net.DialTimeout("tcp", host, 10*time.Second); err == nil {
		_ = conn.Close()
		t.Errorf("%s still accepts connections after Stop", host)
	}
	if response, err := httpClient.Do(request); err == nil {
		_ = response.Body.Close()
		t.Errorf("the directory still answers after Stop with status %d", response.StatusCode)
	}
	ca.Stop()
}

func TestSuggestRenewal(t *testing.T) {
	ctx := testContext(t)
	recs := newRecords()
	ca := Start(t, ServeTXT(t, recs.lookup), shortValidity)
	client := newClient(t, ca, recs)
	account := newAccount(t, ctx, client)
	leaf := obtain(t, ctx, client, account, "default", testDomain)[0]

	start := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	end := start.Add(time.Hour)
	if err := ca.SuggestRenewal(leaf, start, end); err != nil {
		t.Fatalf("SuggestRenewal: %v", err)
	}
	info, err := client.GetRenewalInfo(ctx, leaf)
	if err != nil {
		t.Fatalf("GetRenewalInfo: %v", err)
	}
	if !info.SuggestedWindow.Start.Equal(start) || !info.SuggestedWindow.End.Equal(end) {
		t.Errorf("window = [%v, %v], want [%v, %v]", info.SuggestedWindow.Start, info.SuggestedWindow.End, start, end)
	}
	if info.SelectedTime.Before(start) || info.SelectedTime.After(end) {
		t.Errorf("selected time %v is outside [%v, %v]", info.SelectedTime, start, end)
	}

	if err := ca.SuggestRenewal(leaf, end, start); err == nil {
		t.Error("a window that ends before it starts was accepted")
	}
	if err := ca.SuggestRenewal(selfSigned(t), start, end); err == nil {
		t.Error("a window for a certificate the server never issued was accepted")
	}
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unknown"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
