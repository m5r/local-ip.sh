package e2e

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	renewalPollInterval = 5 * time.Second
	renewalPollLimit    = 10 * time.Minute
	restartPollInterval = 2 * time.Second
	restartPollLimit    = 2 * time.Minute
)

// observation is what the deployment serves at one moment: the leaf of the website's certificate and the published wildcard pair.
type observation struct {
	site *x509.Certificate
	pair keyPair
}

// observe reads both through endpoint, over connections opened for this call alone. A connection kept alive, or a resumed TLS session, would go on showing the certificate of the handshake it began with, and a renewal would never be seen.
func observe(ctx context.Context, tg *target, endpoint netip.AddrPort) (observation, error) {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, endpoint.String())
		},
		TLSClientConfig:   &tls.Config{RootCAs: tg.roots},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	d := tg.domain

	siteResp, _, err := observeGet(ctx, client, "https://"+d+"/")
	if err != nil {
		return observation{}, err
	}
	if siteResp.TLS == nil || len(siteResp.TLS.PeerCertificates) == 0 {
		return observation{}, fmt.Errorf("reading the website's certificate: GET https://%s/ presented no certificate", d)
	}
	site := siteResp.TLS.PeerCertificates[0]
	if !slices.Equal(site.DNSNames, []string{d}) {
		return observation{}, fmt.Errorf("checking the website's certificate: its names are %v, want [%s]", site.DNSNames, d)
	}

	certPEM, err := observeFile(ctx, client, "https://"+d+"/server.pem")
	if err != nil {
		return observation{}, err
	}
	keyPEM, err := observeFile(ctx, client, "https://"+d+"/server.key")
	if err != nil {
		return observation{}, err
	}
	chain, err := parseChain(certPEM)
	if err != nil {
		return observation{}, fmt.Errorf("parsing https://%s/server.pem: %w", d, err)
	}
	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return observation{}, fmt.Errorf("parsing https://%s/server.key: %w", d, err)
	}
	pair := keyPair{chain: chain, signer: signer}
	matches, err := pair.matches()
	if err != nil {
		return observation{}, fmt.Errorf("comparing published key with published certificate: %w", err)
	}
	if !matches {
		return observation{}, errors.New("checking the published pair: the published key does not match the published certificate")
	}
	leaf := pair.leaf()
	if want := []string{"*." + d}; !slices.Equal(leaf.DNSNames, want) {
		return observation{}, fmt.Errorf("checking the published pair: its names are %v, want %v", leaf.DNSNames, want)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       "e2e." + d,
		Roots:         tg.roots,
		Intermediates: pair.intermediates(),
	}); err != nil {
		return observation{}, fmt.Errorf("verifying the published certificate for e2e.%s: %w", d, err)
	}
	return observation{site: site, pair: pair}, nil
}

func observeGet(ctx context.Context, client *http.Client, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("reading body of GET %s: %w", url, err)
	}
	return resp, body, nil
}

func observeFile(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	resp, body, err := observeGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d, want 200", url, resp.StatusCode)
	}
	return body, nil
}

func logStep(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("%s "+format, append([]any{time.Now().UTC().Format(time.RFC3339)}, args...)...)
}

func publicKeyEqual(a, b *x509.Certificate) bool {
	public, ok := a.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && public.Equal(b.PublicKey)
}

// lifecycle forces a renewal of both certificates and checks that both change while DNS keeps answering and the process keeps running, then restarts the server and checks that it serves the stored certificates again.
func lifecycle(t *testing.T, r rig, tg *target) {
	ctx := t.Context()

	logStep(t, "step 1: baseline through port 443 of every address of the website")
	var baseline observation
	for i, addr := range tg.webAddresses {
		obs, err := observe(ctx, tg, netip.AddrPortFrom(addr, 443))
		if err != nil {
			t.Fatalf("baseline through %s: %v", addr, err)
		}
		if i == 0 {
			baseline = obs
			continue
		}
		if obs.site.SerialNumber.Cmp(baseline.site.SerialNumber) != 0 || obs.pair.leaf().SerialNumber.Cmp(baseline.pair.leaf().SerialNumber) != 0 {
			t.Fatalf("%s serves website serial %s and wildcard serial %s, %s serves %s and %s", addr, obs.site.SerialNumber, obs.pair.leaf().SerialNumber, tg.webAddresses[0], baseline.site.SerialNumber, baseline.pair.leaf().SerialNumber)
		}
	}
	baselineContainer, err := r.serverState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	logStep(t, "baseline: website serial %s, wildcard serial %s, container %s started at %s", baseline.site.SerialNumber, baseline.pair.leaf().SerialNumber, baselineContainer.id, baselineContainer.startedAt.Format(time.RFC3339Nano))

	logStep(t, "step 2: starting one prober per name server address, and one of the challenge name")
	probeName := "10-0-0-1." + tg.domain
	probeWant := netip.MustParseAddr("10.0.0.1")
	stops := make([]func() ([]probe, time.Time), len(tg.dnsServers))
	for i, ns := range tg.dnsServers {
		stops[i] = startProber(t, netip.AddrPortFrom(ns, 53), probeName, dns.TypeA, answersAddress(probeWant))
	}
	challengeName := "_acme-challenge." + tg.domain
	stopChallengeProber := startProber(t, netip.AddrPortFrom(tg.dnsServers[0], 53), challengeName, dns.TypeTXT, answersTXT)

	logStep(t, "step 3: sending SIGUSR1 to the server")
	if _, err := r.compose(ctx, dockerCommandTimeout, "kill", "--signal", "SIGUSR1", rigServer); err != nil {
		t.Fatalf("signalling the server: %v", err)
	}

	logStep(t, "step 4: polling through %s until both certificates are renewed", tg.webAddresses[0])
	renewed := pollRenewal(t, tg, baseline)
	logStep(t, "renewed: website serial %s, wildcard serial %s", renewed.site.SerialNumber, renewed.pair.leaf().SerialNumber)
	for _, c := range []struct {
		name     string
		old, new *x509.Certificate
	}{
		{name: "website", old: baseline.site, new: renewed.site},
		{name: "wildcard", old: baseline.pair.leaf(), new: renewed.pair.leaf()},
	} {
		if publicKeyEqual(c.new, c.old) {
			t.Errorf("the renewed %s certificate reuses the public key of the one it replaces", c.name)
		}
		if c.new.NotBefore.Before(c.old.NotBefore) {
			t.Errorf("the renewed %s certificate is valid from %s, earlier than the %s of the one it replaces", c.name, c.new.NotBefore, c.old.NotBefore)
		}
	}

	logStep(t, "step 5: stopping the probers and reading the container's state")
	for i, ns := range tg.dnsServers {
		probes, end := stops[i]()
		silence := longestSilence(probes, end)
		logStep(t, "prober %s: %d probes, %d unanswered, longest silence %s", ns, len(probes), unansweredProbes(probes), silence)
		if silence >= proberSilenceLimit {
			t.Errorf("%s answered no probe for %s during the renewal, want less than %s", ns, silence, proberSilenceLimit)
		}
	}
	// A value is published only while a challenge waits to be validated, so seeing none means that the authority reused an authorization and the renewal validated nothing.
	challengeProbes, _ := stopChallengeProber()
	seen := len(challengeProbes) - unansweredProbes(challengeProbes)
	logStep(t, "challenge prober %s TXT: %d probes, %d saw a value", challengeName, len(challengeProbes), seen)
	if seen == 0 {
		t.Errorf("no probe saw a TXT record at %s during the renewal, so the renewal validated no challenge", challengeName)
	}
	afterRenewal, err := r.serverState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNotRestarted(baselineContainer, afterRenewal); err != nil {
		t.Errorf("after the renewal: %v", err)
	}

	logStep(t, "step 6: restarting the server")
	stopRestartProber := startProber(t, netip.AddrPortFrom(tg.dnsServers[0], 53), probeName, dns.TypeA, answersAddress(probeWant))
	if _, err := r.compose(ctx, dockerCommandTimeout, "restart", rigServer); err != nil {
		t.Fatalf("restarting the server: %v", err)
	}
	afterRestart, err := r.serverState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRestartedInPlace(afterRenewal, afterRestart); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	logStep(t, "container %s started again at %s; polling through %s until it serves both certificates", afterRestart.id, afterRestart.startedAt.Format(time.RFC3339Nano), tg.webAddresses[0])
	restarted := pollObserve(t, tg)
	if restarted.site.SerialNumber.Cmp(renewed.site.SerialNumber) != 0 || restarted.pair.leaf().SerialNumber.Cmp(renewed.pair.leaf().SerialNumber) != 0 {
		t.Errorf("after the restart the website serial is %s and the wildcard serial %s, want the stored %s and %s", restarted.site.SerialNumber, restarted.pair.leaf().SerialNumber, renewed.site.SerialNumber, renewed.pair.leaf().SerialNumber)
	}
	probes, end := stopRestartProber()
	logStep(t, "restart outage through %s: %d probes, %d unanswered, longest silence %s (reported, not judged)", tg.dnsServers[0], len(probes), unansweredProbes(probes), longestSilence(probes, end))
}

func pollRenewal(t *testing.T, tg *target, baseline observation) observation {
	t.Helper()
	endpoint := netip.AddrPortFrom(tg.webAddresses[0], 443)
	deadline := time.Now().Add(renewalPollLimit)
	for {
		obs, err := observe(t.Context(), tg, endpoint)
		switch {
		case err != nil:
			logStep(t, "observing through %s: %v", endpoint, err)
		case obs.site.SerialNumber.Cmp(baseline.site.SerialNumber) != 0 && obs.pair.leaf().SerialNumber.Cmp(baseline.pair.leaf().SerialNumber) != 0:
			return obs
		default:
			logStep(t, "website serial %s, wildcard serial %s", obs.site.SerialNumber, obs.pair.leaf().SerialNumber)
		}
		if time.Now().After(deadline) {
			t.Fatalf("both certificates were not renewed within %s of SIGUSR1", renewalPollLimit)
		}
		if !pause(t.Context(), renewalPollInterval) {
			t.Fatal("test context ended while waiting for the renewal")
		}
	}
}

func pollObserve(t *testing.T, tg *target) observation {
	t.Helper()
	endpoint := netip.AddrPortFrom(tg.webAddresses[0], 443)
	deadline := time.Now().Add(restartPollLimit)
	for {
		obs, err := observe(t.Context(), tg, endpoint)
		if err == nil {
			return obs
		}
		logStep(t, "observing through %s: %v", endpoint, err)
		if time.Now().After(deadline) {
			t.Fatalf("the server served no valid observation within %s of the restart", restartPollLimit)
		}
		if !pause(t.Context(), restartPollInterval) {
			t.Fatal("test context ended while waiting for the server after the restart")
		}
	}
}

// observeFixture is a deployment in miniature: a TLS server that serves the website's certificate and the published pair, both of which the test can replace.
type observeFixture struct {
	rootKey  crypto.Signer
	root     *x509.Certificate
	serial   atomic.Int64
	site     atomic.Pointer[tls.Certificate]
	pairPEM  atomic.Pointer[[2][]byte]
	endpoint netip.AddrPort
}

const observeDomain = "example.test"

func newObserveFixture(t *testing.T) *observeFixture {
	t.Helper()
	f := &observeFixture{}
	f.serial.Store(100)
	rootKey := newECDSAKey(t)
	rootTemplate := caTemplate(1, "observe test root")
	f.rootKey = rootKey
	f.root = issueCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pair := f.pairPEM.Load()
		switch r.URL.Path {
		case "/server.pem":
			w.Write(pair[0])
		case "/server.key":
			w.Write(pair[1])
		default:
			io.WriteString(w, "local-ip.sh")
		}
	}))
	server.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return f.site.Load(), nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.endpoint = netip.MustParseAddrPort(server.Listener.Addr().String())
	return f
}

func (f *observeFixture) issue(t *testing.T, name string, signer crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	return issueCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(f.serial.Add(1)),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, parent, signer.Public(), parentKey)
}

// replace issues and serves a new website certificate and a new wildcard pair, returning both leaves. publishedKey, when not nil, is published in place of the wildcard certificate's own key.
func (f *observeFixture) replace(t *testing.T, siteIssuer *x509.Certificate, siteIssuerKey crypto.Signer, publishedKey crypto.Signer) (site, wildcard *x509.Certificate) {
	t.Helper()
	siteKey := newECDSAKey(t)
	site = f.issue(t, observeDomain, siteKey, siteIssuer, siteIssuerKey)
	f.site.Store(&tls.Certificate{Certificate: [][]byte{site.Raw}, PrivateKey: siteKey, Leaf: site})

	wildcardKey := newECDSAKey(t)
	wildcard = f.issue(t, "*."+observeDomain, wildcardKey, f.root, f.rootKey)
	if publishedKey == nil {
		publishedKey = wildcardKey
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(publishedKey)
	if err != nil {
		t.Fatal(err)
	}
	f.pairPEM.Store(&[2][]byte{pemEncode("CERTIFICATE", wildcard.Raw), pemEncode("PRIVATE KEY", keyDER)})
	return site, wildcard
}

func (f *observeFixture) target() *target {
	return &target{name: "observe fixture", domain: observeDomain, roots: certPool(f.root)}
}

// keptAliveLeaf returns the site leaf seen by a client that keeps its connection, which is what observe must not be.
func keptAliveLeaf(t *testing.T, client *http.Client) *x509.Certificate {
	t.Helper()
	resp, _, err := observeGet(t.Context(), client, "https://"+observeDomain+"/")
	if err != nil {
		t.Fatal(err)
	}
	return resp.TLS.PeerCertificates[0]
}

func TestObserve(t *testing.T) {
	ctx := t.Context()

	t.Run("a replaced certificate is seen", func(t *testing.T) {
		f := newObserveFixture(t)
		tg := f.target()
		firstSite, firstWildcard := f.replace(t, f.root, f.rootKey, nil)

		keptAlive := pinnedClient(t, tg, f.endpoint.Addr())
		keptAlive.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.endpoint.String())
		}
		if leaf := keptAliveLeaf(t, keptAlive); !leaf.Equal(firstSite) {
			t.Fatal("kept-alive client saw another certificate than the first")
		}

		first, err := observe(ctx, tg, f.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if !first.site.Equal(firstSite) || !first.pair.leaf().Equal(firstWildcard) {
			t.Fatal("first observation differs from what was served")
		}

		secondSite, secondWildcard := f.replace(t, f.root, f.rootKey, nil)
		second, err := observe(ctx, tg, f.endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if !second.site.Equal(secondSite) {
			t.Errorf("second observation has website serial %s, want the replacement's %s", second.site.SerialNumber, secondSite.SerialNumber)
		}
		if !second.pair.leaf().Equal(secondWildcard) {
			t.Errorf("second observation has wildcard serial %s, want the replacement's %s", second.pair.leaf().SerialNumber, secondWildcard.SerialNumber)
		}
		if leaf := keptAliveLeaf(t, keptAlive); !leaf.Equal(firstSite) {
			t.Error("kept-alive client saw the replacement, so this test cannot tell a fresh connection from a kept one")
		}
	})

	t.Run("a published key that does not match is an error", func(t *testing.T) {
		f := newObserveFixture(t)
		f.replace(t, f.root, f.rootKey, newECDSAKey(t))
		_, err := observe(ctx, f.target(), f.endpoint)
		expectErrorContains(t, err, "does not match")
	})

	t.Run("a website certificate that does not verify is an error", func(t *testing.T) {
		f := newObserveFixture(t)
		otherKey := newECDSAKey(t)
		otherTemplate := caTemplate(1, "other root")
		other := issueCertificate(t, otherTemplate, otherTemplate, otherKey.Public(), otherKey)
		f.replace(t, other, otherKey, nil)
		_, err := observe(ctx, f.target(), f.endpoint)
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Errorf("observe returned %v, want an unknown authority error", err)
		}
	})

	t.Run("a published pair that does not verify is an error", func(t *testing.T) {
		f := newObserveFixture(t)
		f.replace(t, f.root, f.rootKey, nil)
		tg := f.target()
		otherKey := newECDSAKey(t)
		otherTemplate := caTemplate(1, "other root")
		other := issueCertificate(t, otherTemplate, otherTemplate, otherKey.Public(), otherKey)
		wildcardKey := newECDSAKey(t)
		wildcard := f.issue(t, "*."+observeDomain, wildcardKey, other, otherKey)
		keyDER, err := x509.MarshalPKCS8PrivateKey(wildcardKey)
		if err != nil {
			t.Fatal(err)
		}
		f.pairPEM.Store(&[2][]byte{pemEncode("CERTIFICATE", wildcard.Raw), pemEncode("PRIVATE KEY", keyDER)})
		_, err = observe(ctx, tg, f.endpoint)
		expectErrorContains(t, err, "verifying the published certificate")
	})
}
