package certs

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"github.com/rs/zerolog"

	"local-ip.sh/internal/acmetest"
)

func TestMain(m *testing.M) {
	acmetest.Init()
	os.Exit(m.Run())
}

const (
	testDomain    = "example.com"
	challengeName = "_acme-challenge.example.com"
	shortValidity = 2 * time.Hour
)

var (
	siteNames     = []string{testDomain}
	wildcardNames = []string{"*." + testDomain}
)

// memoryRecords is the zone's challenge record set for tests: the authority publishes into it, and acmetest.ServeTXT answers from it.
type memoryRecords struct {
	mu      sync.Mutex
	values  map[string][]string
	lookups []time.Time
	addedAt time.Time
	// hidden makes the DNS side answer nothing, whatever is published.
	hidden bool
	// addErr is returned by AddChallenge, which then publishes nothing.
	addErr error
	// added, when set, receives a value after each successful AddChallenge, without blocking.
	added chan struct{}
}

// configure changes the behaviour of r under its lock, because the DNS side of the test may already be reading it.
func (r *memoryRecords) configure(change func(*memoryRecords)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	change(r)
}

func recordName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func (r *memoryRecords) AddChallenge(name, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addErr != nil {
		return r.addErr
	}
	if r.values == nil {
		r.values = map[string][]string{}
	}
	name = recordName(name)
	if !slices.Contains(r.values[name], value) {
		r.values[name] = append(r.values[name], value)
	}
	r.addedAt = time.Now()
	select {
	case r.added <- struct{}{}:
	default:
	}
	return nil
}

func (r *memoryRecords) RemoveChallenge(name, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name = recordName(name)
	if i := slices.Index(r.values[name], value); i >= 0 {
		r.values[name] = slices.Delete(r.values[name], i, i+1)
	}
	if len(r.values[name]) == 0 {
		delete(r.values, name)
	}
	return nil
}

func (r *memoryRecords) lookup(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == challengeName {
		r.lookups = append(r.lookups, time.Now())
	}
	if r.hidden {
		return nil
	}
	return slices.Clone(r.values[name])
}

func (r *memoryRecords) published() map[string][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	published := map[string][]string{}
	for name, values := range r.values {
		published[name] = slices.Clone(values)
	}
	return published
}

func assertNothingPublished(t *testing.T, records *memoryRecords) {
	t.Helper()
	if left := records.published(); len(left) != 0 {
		t.Errorf("values still published: %v", left)
	}
}

// logBuffer collects the lines of a zerolog logger that several goroutines write to.
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

// has reports whether a line has the level and the message.
func (b *logBuffer) has(level, message string) bool {
	for line := range strings.SplitSeq(b.String(), "\n") {
		var fields struct{ Level, Message string }
		if json.Unmarshal([]byte(line), &fields) == nil && fields.Level == level && fields.Message == message {
			return true
		}
	}
	return false
}

// testEnv is a certificate authority whose DNS-01 lookups are answered from records.
type testEnv struct {
	ca      *acmetest.CA
	records *memoryRecords
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	records := &memoryRecords{}
	return &testEnv{ca: acmetest.Start(t, acmetest.ServeTXT(t, records.lookup), shortValidity), records: records}
}

// config has a state directory of its own on every call.
func (e *testEnv) config(t *testing.T) Config {
	return Config{
		DirectoryURL:    e.ca.DirectoryURL,
		Domain:          testDomain,
		StateDir:        t.TempDir(),
		Profile:         "default",
		TrustedRoots:    e.ca.APIRoots,
		ValidationDelay: time.Millisecond,
		Records:         e.records,
	}
}

func newTestAuthority(t *testing.T, cfg Config) (*acmeAuthority, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	cfg.Logger = zerolog.New(logs).Level(zerolog.InfoLevel)
	checked, err := checkConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newACMEAuthority(checked)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.httpClient.CloseIdleConnections()
		if t.Failed() {
			t.Logf("log of the authority:\n%s", logs)
		}
	})
	return a, logs
}

// testContext bounds every exchange with the authority so that a hang fails the test instead of blocking the run.
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustIssue(t *testing.T, ctx context.Context, a *acmeAuthority, names []string, replaces *x509.Certificate) (*issuance, *Certificate) {
	t.Helper()
	result, err := a.issue(ctx, names, replaces)
	if err != nil {
		t.Fatalf("issuing %v: %v", names, err)
	}
	certificate, err := newCertificate(result.keyPEM, result.chainPEM, names)
	if err != nil {
		t.Fatalf("the issuance for %v is not a usable certificate: %v", names, err)
	}
	return result, certificate
}

func verifyFor(t *testing.T, c *Certificate, name string, roots *x509.CertPool) {
	t.Helper()
	intermediates := x509.NewCertPool()
	for _, der := range c.TLS.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := c.TLS.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates}); err != nil {
		t.Errorf("certificate does not verify for %s: %v", name, err)
	}
}

func lifetime(leaf *x509.Certificate) time.Duration {
	// Pebble's NotAfter is the last second of validity, inclusive.
	return leaf.NotAfter.Sub(leaf.NotBefore) + time.Second
}

func TestIssueBothCertificates(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	cfg := env.config(t)
	a, _ := newTestAuthority(t, cfg)

	for _, tc := range []struct {
		names    []string
		verifyAs string
	}{
		{siteNames, testDomain},
		{wildcardNames, "anything." + testDomain},
	} {
		result, certificate := mustIssue(t, ctx, a, tc.names, nil)
		verifyFor(t, certificate, tc.verifyAs, env.ca.IssuerRoots)
		key, ok := certificate.TLS.PrivateKey.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() != 2048 {
			t.Errorf("%v: private key is %T, want RSA 2048", tc.names, certificate.TLS.PrivateKey)
		}
		if block, _ := pem.Decode(result.keyPEM); block == nil || block.Type != "RSA PRIVATE KEY" {
			t.Errorf("%v: key PEM is not an RSA PRIVATE KEY block", tc.names)
		}
		if !slices.Equal(certificate.TLS.Leaf.DNSNames, tc.names) {
			t.Errorf("names = %v, want %v", certificate.TLS.Leaf.DNSNames, tc.names)
		}
	}

	if _, err := a.store.loadAccountKey(); err != nil {
		t.Errorf("account.pem does not hold a P-256 key: %v", err)
	}
	firstAccount := a.account.Location

	b, _ := newTestAuthority(t, cfg)
	mustIssue(t, ctx, b, siteNames, nil)
	if b.account.Location != firstAccount {
		t.Errorf("second authority on the same state resolved account %s, want %s", b.account.Location, firstAccount)
	}
	assertNothingPublished(t, env.records)
}

func TestValidationDelay(t *testing.T) {
	t.Run("value published before validation", func(t *testing.T) {
		ctx := testContext(t)
		env := newTestEnv(t)
		cfg := env.config(t)
		cfg.ValidationDelay = 400 * time.Millisecond
		a, _ := newTestAuthority(t, cfg)
		mustIssue(t, ctx, a, siteNames, nil)

		env.records.mu.Lock()
		addedAt, lookups := env.records.addedAt, slices.Clone(env.records.lookups)
		env.records.mu.Unlock()
		if len(lookups) == 0 {
			t.Fatal("the first order of a new account caused no lookup of the challenge name")
		}
		if waited := lookups[0].Sub(addedAt); waited < cfg.ValidationDelay {
			t.Errorf("first lookup came %v after AddChallenge, want at least %v", waited, cfg.ValidationDelay)
		}
	})

	t.Run("cancellation ends the wait", func(t *testing.T) {
		env := newTestEnv(t)
		added := make(chan struct{}, 1)
		env.records.configure(func(r *memoryRecords) { r.added = added })
		cfg := env.config(t)
		cfg.ValidationDelay = time.Minute
		a, _ := newTestAuthority(t, cfg)

		ctx, cancel := context.WithCancel(testContext(t))
		defer cancel()
		go func() {
			select {
			case <-added:
				cancel()
			case <-ctx.Done():
			}
		}()
		start := time.Now()
		_, err := a.issue(ctx, siteNames, nil)
		if elapsed := time.Since(start); elapsed >= cfg.ValidationDelay {
			t.Errorf("issue returned after %v, not before the validation delay of %v was over", elapsed, cfg.ValidationDelay)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		assertNothingPublished(t, env.records)
	})
}

func TestProfile(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	cfg := env.config(t)

	cfg.Profile = "short"
	short, _ := newTestAuthority(t, cfg)
	_, certificate := mustIssue(t, ctx, short, siteNames, nil)
	if got := lifetime(certificate.TLS.Leaf); got != shortValidity {
		t.Errorf("lifetime with the short profile = %v, want %v", got, shortValidity)
	}

	cfg.Profile = "default"
	long, _ := newTestAuthority(t, cfg)
	_, certificate = mustIssue(t, ctx, long, siteNames, nil)
	if got := lifetime(certificate.TLS.Leaf); got != 90*24*time.Hour {
		t.Errorf("lifetime with the default profile = %v, want 90 days", got)
	}

	cfg.Profile = "no-such-profile"
	unknown, _ := newTestAuthority(t, cfg)
	_, err := unknown.issue(ctx, siteNames, nil)
	if err == nil || !strings.Contains(err.Error(), "no-such-profile") {
		t.Errorf("err = %v, want an error that names the profile", err)
	}
	if problem, ok := problemOf(err); ok {
		t.Errorf("an unknown profile gave the problem document %v, want an error of the client", problem)
	}
}

func TestValidationFailureIsAnInspectableProblem(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	env.records.configure(func(r *memoryRecords) { r.hidden = true })
	a, _ := newTestAuthority(t, env.config(t))

	_, err := a.issue(ctx, siteNames, nil)
	if err == nil {
		t.Fatal("issue succeeded although the values were never served")
	}
	problem, ok := problemOf(err)
	if !ok || problem.Type != acme.ProblemTypeUnauthorized || problem.Detail == "" {
		t.Errorf("problemOf(%v) = %+v, %v; want type %s with a detail", err, problem, ok, acme.ProblemTypeUnauthorized)
	}
	assertNothingPublished(t, env.records)
}

func TestRecordsErrorFailsTheOrder(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	refused := errors.New("the zone refuses the value")
	env.records.configure(func(r *memoryRecords) { r.addErr = refused })
	a, _ := newTestAuthority(t, env.config(t))

	if _, err := a.issue(ctx, siteNames, nil); !errors.Is(err, refused) {
		t.Errorf("err = %v, want one that wraps %v", err, refused)
	}
}

// countingServer is an HTTPS endpoint that counts its requests and answers them with respond.
func countingServer(t *testing.T, respond http.HandlerFunc) (cfg func(Config) Config, requests *atomic.Int64) {
	t.Helper()
	requests = &atomic.Int64{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return func(c Config) Config {
		c.DirectoryURL = server.URL + "/directory"
		c.TrustedRoots = roots
		return c
	}, requests
}

func TestAccountKeyIsStoredBeforeItIsUsed(t *testing.T) {
	skipWithoutPermissions(t)
	ctx := testContext(t)
	pointAt, requests := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nothing here", http.StatusNotFound)
	})
	cfg := pointAt(Config{Domain: testDomain, StateDir: t.TempDir(), Profile: "default", ValidationDelay: time.Millisecond, Records: &memoryRecords{}})
	if err := os.Chmod(cfg.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfg.StateDir, 0o700) })
	a, _ := newTestAuthority(t, cfg)

	if _, err := a.issue(ctx, siteNames, nil); err == nil {
		t.Fatal("issue succeeded without a place to store the account key")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the authority received %d requests, want none before the key is stored", n)
	}
}

func TestUnusableAccountKeyIsReplaced(t *testing.T) {
	env := newTestEnv(t)
	for _, tc := range unusableAccountKeys(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testContext(t)
			a, logs := newTestAuthority(t, env.config(t))
			writeTestFile(t, a.store.accountKeyPath(), tc.content)

			mustIssue(t, ctx, a, siteNames, nil)
			if !logs.has("warn", "Replacing unusable ACME account key") {
				t.Error("no warning about the unusable key")
			}
			if _, err := a.store.loadAccountKey(); err != nil {
				t.Errorf("account.pem after the issue: %v", err)
			}
		})
	}
}

func TestUnreadableAccountKeyFailsTheOrder(t *testing.T) {
	skipWithoutPermissions(t)
	ctx := testContext(t)
	env := newTestEnv(t)
	a, _ := newTestAuthority(t, env.config(t))
	if err := a.store.saveAccountKey(newECKey(t, elliptic.P256())); err != nil {
		t.Fatal(err)
	}
	path := a.store.accountKeyPath()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := a.issue(ctx, siteNames, nil); err == nil {
		t.Error("issue succeeded with an unreadable account key")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the unreadable account key was replaced")
	}
}

func TestForgottenAccountIsRegisteredAgain(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	a, _ := newTestAuthority(t, env.config(t))
	_, first := mustIssue(t, ctx, a, siteNames, nil)
	firstAccount := a.account.Location
	keyBefore, err := os.ReadFile(a.store.accountKeyPath())
	if err != nil {
		t.Fatal(err)
	}

	env.ca.Forget()

	_, err = a.issue(ctx, siteNames, first.TLS.Leaf)
	if problem, ok := problemOf(err); !ok || problem.Type != acme.ProblemTypeAccountDoesNotExist {
		t.Fatalf("issue after Forget: err = %v, want a problem of type %s", err, acme.ProblemTypeAccountDoesNotExist)
	}
	mustIssue(t, ctx, a, siteNames, nil)
	keyAfter, err := os.ReadFile(a.store.accountKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Error("the account key file changed")
	}
	if a.account.Location == firstAccount {
		t.Errorf("the account was not registered again: same URL %s", firstAccount)
	}
}

func TestAccountKeyIsReadAgainAfterAFailure(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	a, _ := newTestAuthority(t, env.config(t))
	mustIssue(t, ctx, a, siteNames, nil)
	firstAccount := a.account.Location
	keyBefore, err := os.ReadFile(a.store.accountKeyPath())
	if err != nil {
		t.Fatal(err)
	}

	// A cancelled context fails the order whatever the authority would do: a valid authorization it reuses would let any failure caused through DNS pass.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.issue(cancelled, siteNames, nil); err == nil {
		t.Fatal("issue with a cancelled context succeeded")
	}
	if err := os.Remove(a.store.accountKeyPath()); err != nil {
		t.Fatal(err)
	}

	mustIssue(t, ctx, a, siteNames, nil)
	keyAfter, err := os.ReadFile(a.store.accountKeyPath())
	if err != nil {
		t.Fatalf("no account key after the issue: %v", err)
	}
	if bytes.Equal(keyBefore, keyAfter) {
		t.Error("the removed account key came back")
	}
	if a.account.Location == firstAccount {
		t.Errorf("the new key was not registered: same account %s", firstAccount)
	}
}

func TestReplaces(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	a, _ := newTestAuthority(t, env.config(t))
	_, first := mustIssue(t, ctx, a, siteNames, nil)
	_, second := mustIssue(t, ctx, a, siteNames, first.TLS.Leaf)
	_, third := mustIssue(t, ctx, a, siteNames, first.TLS.Leaf)
	if second.TLS.Leaf.SerialNumber.Cmp(third.TLS.Leaf.SerialNumber) == 0 {
		t.Error("the two replacements have the same serial number")
	}
}

func TestRenewalInfo(t *testing.T) {
	ctx := testContext(t)
	env := newTestEnv(t)
	a, _ := newTestAuthority(t, env.config(t))
	result, certificate := mustIssue(t, ctx, a, siteNames, nil)
	if result.renewal == nil {
		t.Error("the issuance carries no renewal information although the authority publishes it")
	} else if result.renewal.checkAfter < time.Minute || result.renewal.checkAfter > 24*time.Hour {
		t.Errorf("checkAfter of the issuance = %v, want between 1 minute and 24 hours", result.renewal.checkAfter)
	}

	start := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	end := start.Add(time.Hour)
	if err := env.ca.SuggestRenewal(certificate.TLS.Leaf, start, end); err != nil {
		t.Fatal(err)
	}
	info, ok, err := a.renewalInfo(ctx, certificate.TLS.Leaf)
	if err != nil || !ok {
		t.Fatalf("renewalInfo = %+v, %v, %v", info, ok, err)
	}
	if info.renewAt.Before(start) || info.renewAt.After(end) {
		t.Errorf("renewAt = %v, want inside [%v, %v]", info.renewAt, start, end)
	}
	if info.checkAfter < time.Minute || info.checkAfter > 24*time.Hour {
		t.Errorf("checkAfter = %v, want between 1 minute and 24 hours", info.checkAfter)
	}
}

// stubTransport answers every request with the status and Retry-After header the request asks for in its own headers, so that concurrent requests do not share state.
type stubTransport struct {
	requests atomic.Int64
}

func (s *stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	s.requests.Add(1)
	status, err := strconv.Atoi(request.Header.Get("X-Status"))
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	if value := request.Header.Get("X-Retry-After"); value != "" {
		header.Set("Retry-After", value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: http.NoBody, Request: request}, nil
}

func TestRetryAfterRecorder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stub := &stubTransport{}
		var sent atomic.Int64
		send := func(r *retryAfterRecorder, status int, retryAfter string) {
			request, err := http.NewRequest(http.MethodGet, "https://ca.test/directory", nil)
			if err != nil {
				t.Error(err)
				return
			}
			request.Header.Set("X-Status", strconv.Itoa(status))
			request.Header.Set("X-Retry-After", retryAfter)
			sent.Add(1)
			response, err := r.RoundTrip(request)
			if err != nil {
				t.Error(err)
				return
			}
			_ = response.Body.Close()
		}
		fresh := func() *retryAfterRecorder { return &retryAfterRecorder{next: stub} }
		expect := func(what string, r *retryAfterRecorder, want time.Time) {
			t.Helper()
			if got := r.waitUntil(); !got.Equal(want) {
				t.Errorf("%s: waitUntil = %v, want %v", what, got, want)
			}
		}

		for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
			r := fresh()
			send(r, status, "120")
			expect(fmt.Sprintf("%d with 120 seconds", status), r, time.Now().Add(120*time.Second))
		}

		r := fresh()
		date := time.Now().Add(90 * time.Minute).UTC()
		send(r, http.StatusServiceUnavailable, date.Format(http.TimeFormat))
		expect("HTTP date", r, date)

		r = fresh()
		send(r, http.StatusTooManyRequests, strconv.Itoa(10*24*60*60))
		expect("ten days", r, time.Now().Add(24*time.Hour))

		r = fresh()
		send(r, http.StatusTooManyRequests, "99999999999999999999999")
		expect("a number of seconds beyond any integer", r, time.Now().Add(24*time.Hour))

		r = fresh()
		first := time.Now().Add(300 * time.Second)
		send(r, http.StatusServiceUnavailable, "300")
		time.Sleep(time.Minute)
		send(r, http.StatusServiceUnavailable, "10")
		expect("a later and shorter value", r, first)

		for _, tc := range []struct {
			status     int
			retryAfter string
		}{
			{http.StatusOK, "120"},
			{http.StatusServiceUnavailable, "soon"},
			{http.StatusTooManyRequests, "-5"},
			{http.StatusInternalServerError, ""},
			{http.StatusInternalServerError, "120"},
			{http.StatusTooManyRequests, ""},
		} {
			r := fresh()
			send(r, tc.status, tc.retryAfter)
			expect(fmt.Sprintf("%d with %q", tc.status, tc.retryAfter), r, time.Time{})
		}

		r = fresh()
		send(r, http.StatusServiceUnavailable, "120")
		time.Sleep(119 * time.Second)
		if r.waitUntil().IsZero() {
			t.Error("the moment was forgotten before it passed")
		}
		time.Sleep(time.Second)
		expect("once the moment has passed", r, time.Time{})

		r = fresh()
		var wg sync.WaitGroup
		for i := 1; i <= 8; i++ {
			wg.Go(func() { send(r, http.StatusTooManyRequests, strconv.Itoa(i*10)) })
		}
		wg.Wait()
		expect("concurrent answers", r, time.Now().Add(80*time.Second))

		if got, want := stub.requests.Load(), sent.Load(); got != want {
			t.Errorf("the stub received %d requests, want %d", got, want)
		}
	})
}

func TestRetryAfterReachesTheAuthority(t *testing.T) {
	ctx := testContext(t)
	pointAt, requests := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:serverInternal","detail":"busy"}`)
	})
	cfg := pointAt(Config{Domain: testDomain, StateDir: t.TempDir(), Profile: "default", ValidationDelay: time.Millisecond, Records: &memoryRecords{}})
	a, _ := newTestAuthority(t, cfg)

	if _, err := a.issue(ctx, siteNames, nil); err == nil {
		t.Fatal("issue succeeded against an authority that refuses everything")
	}
	if ahead := time.Until(a.waitUntil()); ahead < 100*time.Second || ahead > 120*time.Second {
		t.Errorf("waitUntil is %v ahead, want about 120 seconds", ahead)
	}
	if n := requests.Load(); n < 1 || n > 3 {
		t.Errorf("the authority received %d requests, want 1 to 3", n)
	}
}

func TestProblemOf(t *testing.T) {
	problem := acme.Problem{Type: acme.ProblemTypeUnauthorized, Detail: "no"}
	if got, ok := problemOf(fmt.Errorf("ordering: %w", problem)); !ok || got.Type != problem.Type {
		t.Errorf("value: problemOf = %+v, %v", got, ok)
	}
	if got, ok := problemOf(wrapped{&problem}); !ok || got.Type != problem.Type {
		t.Errorf("pointer: problemOf = %+v, %v", got, ok)
	}
	if got, ok := problemOf(wrapped{(*acme.Problem)(nil)}); ok {
		t.Errorf("typed nil pointer: problemOf = %+v, true", got)
	}
	if got, ok := problemOf(errors.New("timeout")); ok {
		t.Errorf("no problem: problemOf = %+v, true", got)
	}
}

// wrapped carries an error the way the library wraps an order's problem, which may be a typed nil pointer.
type wrapped struct{ err error }

func (w wrapped) Error() string { return "order failed" }
func (w wrapped) Unwrap() error { return w.err }
