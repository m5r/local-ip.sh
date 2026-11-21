package e2e

import (
	"cmp"
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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	lifecycleConfigEnv = "E2E_LIFECYCLE_FLY_CONFIG"
	flyTokenEnv        = "FLY_API_TOKEN"

	renewalPollInterval = 5 * time.Second
	renewalPollLimit    = 10 * time.Minute
	restartPollInterval = 2 * time.Second
	restartPollLimit    = 2 * time.Minute
)

// lifecycleApp is the only deployment this test may signal and restart.
const lifecycleApp = "local-ip-staging"

const lifecycleRefusal = "this test forces certificate renewals and restarts the machine, and only runs against " + lifecycleApp + " with Let's Encrypt's staging environment"

// lifecycleGuard refuses a target that is not the staging deployment according to the local Fly config.
func lifecycleGuard(tg *target) error {
	if tg.app != lifecycleApp || !tg.stagingCA {
		return fmt.Errorf("refusing to run against %s: %s", tg.app, lifecycleRefusal)
	}
	return nil
}

// machineGuard refuses a machine whose own configuration does not say what the local Fly config says: the local file is only a claim about the deployment.
func machineGuard(tg *target, machine flyMachine) error {
	var differences []string
	env := machine.Config.Env
	staging, present := env["XIP_STAGING"]
	if !present {
		differences = append(differences, "its environment has no XIP_STAGING")
	} else if parsed, err := strconv.ParseBool(staging); err != nil || !parsed {
		differences = append(differences, fmt.Sprintf("its XIP_STAGING is %q, not true", staging))
	}
	domain, present := env["XIP_DOMAIN"]
	if !present {
		differences = append(differences, "its environment has no XIP_DOMAIN")
	} else if canonical := strings.TrimSuffix(strings.ToLower(domain), "."); canonical != tg.domain {
		differences = append(differences, fmt.Sprintf("its XIP_DOMAIN is %q, not %q", domain, tg.domain))
	}
	if len(differences) > 0 {
		return fmt.Errorf("refusing to run against machine %s of %s: %s; %s", machine.ID, tg.app, strings.Join(differences, ", "), lifecycleRefusal)
	}
	return nil
}

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

func describeMachines(machines []flyMachine) string {
	parts := make([]string, len(machines))
	for i, m := range machines {
		parts[i] = m.ID + " (" + m.State + ")"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func describeEvents(events []flyMachineEvent) string {
	parts := make([]string, len(events))
	for i, e := range events {
		parts[i] = fmt.Sprintf("%s/%s at %s", e.Type, e.Status, e.time().Format(time.RFC3339Nano))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func newestEvent(events []flyMachineEvent) (flyMachineEvent, bool) {
	if len(events) == 0 {
		return flyMachineEvent{}, false
	}
	return slices.MaxFunc(events, func(a, b flyMachineEvent) int { return cmp.Compare(a.Timestamp, b.Timestamp) }), true
}

// eventsAfter returns the events that are not among seen and not older than the newest of them: the API lists only the last few events, so identity alone cannot tell an old event that scrolled back into view from a new one, and time alone cannot separate two events of the same millisecond.
func eventsAfter(events []flyMachineEvent, seen []flyMachineEvent) []flyMachineEvent {
	var newestSeen int64
	for _, e := range seen {
		newestSeen = max(newestSeen, e.Timestamp)
	}
	var after []flyMachineEvent
	for _, e := range events {
		if e.Timestamp >= newestSeen && !slices.ContainsFunc(seen, func(s flyMachineEvent) bool { return s.ID == e.ID }) {
			after = append(after, e)
		}
	}
	return after
}

func publicKeyEqual(a, b *x509.Certificate) bool {
	public, ok := a.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && public.Equal(b.PublicKey)
}

func TestStagingLifecycle(t *testing.T) {
	configPath, set := os.LookupEnv(lifecycleConfigEnv)
	if !set {
		t.Skipf("%s is not set; set it to the path of the staging Fly config to run the lifecycle test", lifecycleConfigEnv)
	}
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		t.Fatalf("%s is set but empty; set it to the path of the staging Fly config, or unset it to skip the lifecycle test", lifecycleConfigEnv)
	}
	token, set := os.LookupEnv(flyTokenEnv)
	if !set {
		t.Fatalf("%s is not set; the lifecycle test needs a Fly API token limited to %s", flyTokenEnv, lifecycleApp)
	}
	ctx := t.Context()

	logStep(t, "step 1: checking the target")
	tg, err := loadTarget(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycleGuard(tg); err != nil {
		t.Fatal(err)
	}
	fly, err := newFlyMachines(tg.app, token)
	if err != nil {
		t.Fatal(err)
	}
	machines, err := fly.list(ctx)
	if err != nil {
		t.Fatalf("listing the machines of %s: %v", tg.app, err)
	}
	if len(machines) != 1 || machines[0].State != "started" {
		t.Fatalf("%s has machines %s, want exactly one in state started", tg.app, describeMachines(machines))
	}
	machine := machines[0]
	if err := machineGuard(tg, machine); err != nil {
		t.Fatal(err)
	}
	id := machine.ID
	logStep(t, "target: app %s, domain %s, machine %s, nameservers %v", tg.app, tg.domain, id, tg.nameServers)

	logStep(t, "step 2: baseline through port 443 of every nameserver")
	var baseline observation
	for i, ns := range tg.nameServers {
		obs, err := observe(ctx, tg, netip.AddrPortFrom(ns, 443))
		if err != nil {
			t.Fatalf("baseline through %s: %v", ns, err)
		}
		if i == 0 {
			baseline = obs
			continue
		}
		if obs.site.SerialNumber.Cmp(baseline.site.SerialNumber) != 0 || obs.pair.leaf().SerialNumber.Cmp(baseline.pair.leaf().SerialNumber) != 0 {
			t.Fatalf("%s serves website serial %s and wildcard serial %s, %s serves %s and %s", ns, obs.site.SerialNumber, obs.pair.leaf().SerialNumber, tg.nameServers[0], baseline.site.SerialNumber, baseline.pair.leaf().SerialNumber)
		}
	}
	baselineEvent, ok := newestEvent(machine.Events)
	if !ok {
		t.Fatalf("machine %s lists no event, so a restart could not be told apart from a renewal", id)
	}
	logStep(t, "baseline: website serial %s, wildcard serial %s, newest event %s %s/%s at %s", baseline.site.SerialNumber, baseline.pair.leaf().SerialNumber, baselineEvent.ID, baselineEvent.Type, baselineEvent.Status, baselineEvent.time().Format(time.RFC3339Nano))

	logStep(t, "step 3: starting one prober per nameserver")
	probeName := "10-0-0-1." + tg.domain
	probeWant := netip.MustParseAddr("10.0.0.1")
	stops := make([]func() ([]probe, time.Time), len(tg.nameServers))
	for i, ns := range tg.nameServers {
		stops[i] = startProber(t, netip.AddrPortFrom(ns, 53), probeName, probeWant)
	}

	logStep(t, "step 4: sending SIGUSR1 to machine %s", id)
	if err := fly.signal(ctx, id, "SIGUSR1"); err != nil {
		t.Fatalf("signalling machine %s: %v", id, err)
	}

	logStep(t, "step 5: polling through %s until both certificates are renewed", tg.nameServers[0])
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

	logStep(t, "step 6: stopping the probers and reading the machine's events")
	for i, ns := range tg.nameServers {
		probes, end := stops[i]()
		silence := longestSilence(probes, end)
		logStep(t, "prober %s: %d probes, %d unanswered, longest silence %s", ns, len(probes), unansweredProbes(probes), silence)
		if silence >= proberSilenceLimit {
			t.Errorf("%s answered no probe for %s during the renewal, want less than %s", ns, silence, proberSilenceLimit)
		}
	}
	afterRenewal, err := fly.get(ctx, id)
	if err != nil {
		t.Fatalf("reading machine %s: %v", id, err)
	}
	if afterRenewal.State != "started" {
		t.Fatalf("machine %s is in state %s after the renewal, want started", id, afterRenewal.State)
	}
	if !slices.ContainsFunc(afterRenewal.Events, func(e flyMachineEvent) bool { return e.ID == baselineEvent.ID }) {
		t.Errorf("machine %s no longer lists the baseline event %s, so nothing can be concluded about restarts; events: %s", id, baselineEvent.ID, describeEvents(afterRenewal.Events))
	} else {
		for _, e := range eventsAfter(afterRenewal.Events, machine.Events) {
			if e.Type == "exit" || e.Type == "start" {
				t.Errorf("machine %s has a %s/%s event at %s after the baseline: the process that renewed is not the one that was running", id, e.Type, e.Status, e.time().Format(time.RFC3339Nano))
			}
		}
	}

	logStep(t, "step 7: restarting machine %s", id)
	stopRestartProber := startProber(t, netip.AddrPortFrom(tg.nameServers[0], 53), probeName, probeWant)
	if err := fly.restart(ctx, id); err != nil {
		t.Fatalf("restarting machine %s: %v", id, err)
	}
	waitRestarted(t, fly, id, afterRenewal.Events)
	logStep(t, "machine %s started again; polling through %s until it serves both certificates", id, tg.nameServers[0])
	restarted := pollObserve(t, tg)
	if restarted.site.SerialNumber.Cmp(renewed.site.SerialNumber) != 0 || restarted.pair.leaf().SerialNumber.Cmp(renewed.pair.leaf().SerialNumber) != 0 {
		t.Errorf("after the restart the website serial is %s and the wildcard serial %s, want the stored %s and %s", restarted.site.SerialNumber, restarted.pair.leaf().SerialNumber, renewed.site.SerialNumber, renewed.pair.leaf().SerialNumber)
	}
	probes, end := stopRestartProber()
	logStep(t, "restart outage through %s: %d probes, %d unanswered, longest silence %s (reported, not judged)", tg.nameServers[0], len(probes), unansweredProbes(probes), longestSilence(probes, end))
}

func pollRenewal(t *testing.T, tg *target, baseline observation) observation {
	t.Helper()
	endpoint := netip.AddrPortFrom(tg.nameServers[0], 443)
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

func waitRestarted(t *testing.T, fly *flyMachines, id string, seen []flyMachineEvent) {
	t.Helper()
	deadline := time.Now().Add(restartPollLimit)
	var newer []flyMachineEvent
	for {
		machine, err := fly.get(t.Context(), id)
		if err != nil {
			logStep(t, "reading machine %s: %v", id, err)
		} else {
			newer = eventsAfter(machine.Events, seen)
			if slices.ContainsFunc(newer, func(e flyMachineEvent) bool { return e.Type == "start" && e.Status == "started" }) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("machine %s has no start/started event within %s of the restart; newer events: %s", id, restartPollLimit, describeEvents(newer))
		}
		if !pause(t.Context(), restartPollInterval) {
			t.Fatal("test context ended while waiting for the restart")
		}
	}
}

func pollObserve(t *testing.T, tg *target) observation {
	t.Helper()
	endpoint := netip.AddrPortFrom(tg.nameServers[0], 443)
	deadline := time.Now().Add(restartPollLimit)
	for {
		obs, err := observe(t.Context(), tg, endpoint)
		if err == nil {
			return obs
		}
		logStep(t, "observing through %s: %v", endpoint, err)
		if time.Now().After(deadline) {
			t.Fatalf("the deployment served no valid observation within %s of the restart", restartPollLimit)
		}
		if !pause(t.Context(), restartPollInterval) {
			t.Fatal("test context ended while waiting for the deployment after the restart")
		}
	}
}

func TestEventsAfter(t *testing.T) {
	event := func(id, kind string, timestamp int64) flyMachineEvent {
		return flyMachineEvent{ID: id, Type: kind, Status: "x", Timestamp: timestamp}
	}
	ids := func(events []flyMachineEvent) []string {
		out := make([]string, len(events))
		for i, e := range events {
			out[i] = e.ID
		}
		return out
	}

	tests := []struct {
		name   string
		events []flyMachineEvent
		seen   []flyMachineEvent
		want   []string
	}{
		{name: "nothing new", events: []flyMachineEvent{event("b", "start", 2000), event("a", "launch", 1000)}, seen: []flyMachineEvent{event("b", "start", 2000), event("a", "launch", 1000)}, want: []string{}},
		{name: "a later event", events: []flyMachineEvent{event("c", "exit", 3000), event("b", "start", 2000)}, seen: []flyMachineEvent{event("b", "start", 2000), event("a", "launch", 1000)}, want: []string{"c"}},
		{name: "an unseen event older than the newest seen", events: []flyMachineEvent{event("b", "start", 2000), event("z", "exit", 1500)}, seen: []flyMachineEvent{event("b", "start", 2000)}, want: []string{}},
		{name: "same timestamp as the newest seen, seen", events: []flyMachineEvent{event("b", "start", 2000), event("s", "exit", 2000)}, seen: []flyMachineEvent{event("b", "launch", 2000), event("s", "exit", 2000)}, want: []string{}},
		{name: "same timestamp as the newest seen, not seen", events: []flyMachineEvent{event("n", "exit", 2000), event("b", "start", 2000)}, seen: []flyMachineEvent{event("b", "start", 2000)}, want: []string{"n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ids(eventsAfter(tt.events, tt.seen)); !slices.Equal(got, tt.want) {
				t.Errorf("eventsAfter = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLifecycleGuard(t *testing.T) {
	staging, err := loadTarget(filepath.Join("..", "fly.staging.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lifecycleGuard(staging); err != nil {
		t.Errorf("fly.staging.toml refused: %v", err)
	}

	refused := []struct {
		name       string
		configPath func(t *testing.T) string
		app        string
	}{
		{name: "the repository's fly.toml", configPath: func(*testing.T) string { return filepath.Join("..", "fly.toml") }, app: "local-ip"},
		{name: "production app with XIP_STAGING", configPath: func(t *testing.T) string {
			return writeConfig(t, flyConfig(`"local-ip"`, validEnv(map[string]string{"XIP_STAGING": `"true"`})))
		}, app: "local-ip"},
		{name: "staging app without XIP_STAGING", configPath: func(t *testing.T) string {
			return writeConfig(t, flyConfig(`"`+lifecycleApp+`"`, validEnv(nil)))
		}, app: lifecycleApp},
		{name: "staging app with XIP_STAGING false", configPath: func(t *testing.T) string {
			return writeConfig(t, flyConfig(`"`+lifecycleApp+`"`, validEnv(map[string]string{"XIP_STAGING": `"false"`})))
		}, app: lifecycleApp},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			tg, err := loadTarget(tt.configPath(t))
			if err != nil {
				t.Fatal(err)
			}
			err = lifecycleGuard(tg)
			expectErrorContains(t, err, "refusing to run against "+tt.app+": "+lifecycleRefusal)
		})
	}
}

func TestMachineGuard(t *testing.T) {
	tg := &target{app: lifecycleApp, domain: "xip-staging.local-ip.sh"}
	machine := func(env map[string]string) flyMachine {
		return flyMachine{ID: "d8901", State: "started", Config: flyMachineConfig{Env: env}}
	}

	accepted := []struct {
		name string
		env  map[string]string
	}{
		{name: "staging and the target's domain", env: map[string]string{"XIP_STAGING": "true", "XIP_DOMAIN": "xip-staging.local-ip.sh"}},
		{name: "domain in another case", env: map[string]string{"XIP_STAGING": "1", "XIP_DOMAIN": "XIP-Staging.Local-IP.sh"}},
		{name: "domain with a trailing dot", env: map[string]string{"XIP_STAGING": "TRUE", "XIP_DOMAIN": "xip-staging.local-ip.sh."}},
	}
	for _, tt := range accepted {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			if err := machineGuard(tg, machine(tt.env)); err != nil {
				t.Error(err)
			}
		})
	}

	refused := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "XIP_STAGING missing", env: map[string]string{"XIP_DOMAIN": "xip-staging.local-ip.sh"}, wantErr: "no XIP_STAGING"},
		{name: "XIP_STAGING false", env: map[string]string{"XIP_STAGING": "false", "XIP_DOMAIN": "xip-staging.local-ip.sh"}, wantErr: `XIP_STAGING is "false"`},
		{name: "XIP_STAGING not a boolean", env: map[string]string{"XIP_STAGING": "yes", "XIP_DOMAIN": "xip-staging.local-ip.sh"}, wantErr: `XIP_STAGING is "yes"`},
		{name: "another domain", env: map[string]string{"XIP_STAGING": "true", "XIP_DOMAIN": "local-ip.sh"}, wantErr: `XIP_DOMAIN is "local-ip.sh", not "xip-staging.local-ip.sh"`},
		{name: "domain missing", env: map[string]string{"XIP_STAGING": "true"}, wantErr: "no XIP_DOMAIN"},
		{name: "no environment at all", env: nil, wantErr: "no XIP_STAGING"},
	}
	for _, tt := range refused {
		t.Run("refuses "+tt.name, func(t *testing.T) {
			err := machineGuard(tg, machine(tt.env))
			expectErrorContains(t, err, "refusing to run against machine d8901 of "+lifecycleApp)
			expectErrorContains(t, err, tt.wantErr)
			expectErrorContains(t, err, lifecycleRefusal)
		})
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
	return &target{app: lifecycleApp, domain: observeDomain, roots: certPool(f.root)}
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
