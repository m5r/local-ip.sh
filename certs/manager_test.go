package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"github.com/rs/zerolog"
)

const (
	day      = 24 * time.Hour
	validity = 90 * day
	// renewalAge is how long after its start a certificate of 90 days reaches its renewal deadline.
	renewalAge = 60 * day
)

// seconds is a moment of virtual time, counted from the start of the fake authority.
func seconds(d time.Duration) int {
	return int(d / time.Second)
}

func secondsOf(d time.Duration) string {
	return fmt.Sprint(seconds(d))
}

// issueCall is one call of the fake's issue, recorded when it arrives.
type issueCall struct {
	id       string
	at       time.Duration
	replaces *x509.Certificate
	// nth counts the calls for the same certificate, from 1.
	nth int
}

type infoCall struct {
	id   string
	at   time.Duration
	leaf *x509.Certificate
}

// fakeAuthority stands for an authority whose clock is right: its certificates start at the moment it is asked, read with time.Now and never with the manager's wall clock.
type fakeAuthority struct {
	start time.Time

	mu     sync.Mutex
	issues []issueCall
	infos  []infoCall
	until  time.Time
	// onIssue decides the outcome of an order once its duration has passed; nil or a nil error issues a certificate.
	onIssue func(ctx context.Context, call issueCall) error
	// onRenewalInfo answers renewalInfo; nil answers that the authority publishes no renewal information.
	onRenewalInfo func(ctx context.Context, call infoCall) (renewalInfo, bool, error)
	// duration is how long an order takes.
	duration time.Duration
	// backdate moves the start of the certificates it issues into the past.
	backdate time.Duration
	lifetime time.Duration
	// attach is the renewal information sent with every certificate, if any.
	attach *renewalInfo
}

var _ authority = (*fakeAuthority)(nil)

func newFakeAuthority() *fakeAuthority {
	return &fakeAuthority{start: time.Now(), lifetime: validity}
}

func (f *fakeAuthority) set(change func(*fakeAuthority)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func idOf(names []string) string {
	if slices.Equal(names, siteNames) {
		return "site"
	}
	return "wildcard"
}

func (f *fakeAuthority) issue(ctx context.Context, names []string, replaces *x509.Certificate) (*issuance, error) {
	asked := time.Now()
	f.mu.Lock()
	call := issueCall{id: idOf(names), at: asked.Sub(f.start), replaces: replaces, nth: 1}
	for _, previous := range f.issues {
		if previous.id == call.id {
			call.nth++
		}
	}
	f.issues = append(f.issues, call)
	onIssue, duration, backdate, lifetime, attach := f.onIssue, f.duration, f.backdate, f.lifetime, f.attach
	f.mu.Unlock()

	if duration > 0 {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if onIssue != nil {
		if err := onIssue(ctx, call); err != nil {
			return nil, err
		}
	}
	keyPEM, chainPEM, err := makeChain(names, asked.Add(-backdate), lifetime)
	if err != nil {
		return nil, err
	}
	result := &issuance{keyPEM: keyPEM, chainPEM: chainPEM}
	if attach != nil {
		info := *attach
		result.renewal = &info
	}
	return result, nil
}

func (f *fakeAuthority) renewalInfo(ctx context.Context, leaf *x509.Certificate) (renewalInfo, bool, error) {
	f.mu.Lock()
	call := infoCall{id: idOf(leaf.DNSNames), at: time.Since(f.start), leaf: leaf}
	f.infos = append(f.infos, call)
	onRenewalInfo := f.onRenewalInfo
	f.mu.Unlock()
	if onRenewalInfo == nil {
		return renewalInfo{}, false, nil
	}
	return onRenewalInfo(ctx, call)
}

func (f *fakeAuthority) waitUntil() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Now().Before(f.until) {
		return f.until
	}
	return time.Time{}
}

// issued returns the arrival times of the orders for id, in seconds.
func (f *fakeAuthority) issued(id string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var times []int
	for _, call := range f.issues {
		if id == "" || call.id == id {
			times = append(times, seconds(call.at))
		}
	}
	return times
}

func (f *fakeAuthority) calls() []issueCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.issues)
}

func (f *fakeAuthority) asked(id string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var times []int
	for _, call := range f.infos {
		if id == "" || call.id == id {
			times = append(times, seconds(call.at))
		}
	}
	return times
}

// makeChain returns a self-signed ECDSA certificate for names, valid from notBefore for lifetime, as the key block and the chain.
func makeChain(names []string, notBefore time.Time, lifetime time.Duration) (keyPEM, chainPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func makeCertificate(t *testing.T, names []string, notBefore time.Time, lifetime time.Duration) *Certificate {
	t.Helper()
	keyPEM, chainPEM, err := makeChain(names, notBefore, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := newCertificate(keyPEM, chainPEM, names)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// freshCertificate is valid for 90 days from now; dueCertificate has been valid for 80 days and stays so for 10 more, so it is past its renewal deadline.
func freshCertificate(t *testing.T, names []string) *Certificate {
	return makeCertificate(t, names, time.Now(), validity)
}

func dueCertificate(t *testing.T, names []string) *Certificate {
	return makeCertificate(t, names, time.Now().Add(-80*day), validity)
}

func managerConfig(stateDir string, logs *logBuffer) Config {
	return Config{
		DirectoryURL: "https://ca.test/directory",
		Domain:       testDomain,
		StateDir:     stateDir,
		Records:      &memoryRecords{},
		Logger:       zerolog.New(logs),
	}
}

func storeFor(t *testing.T, stateDir string) *store {
	t.Helper()
	cfg, err := checkConfig(managerConfig(stateDir, &logBuffer{}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func storeCertificate(t *testing.T, stateDir, id string, c *Certificate) {
	t.Helper()
	if err := storeFor(t, stateDir).saveCertificate(id, c); err != nil {
		t.Fatal(err)
	}
}

// harness is a manager on a fake authority, inside a synctest bubble.
type harness struct {
	t        *testing.T
	stateDir string
	fake     *fakeAuthority
	logs     *logBuffer
	m        *Manager
	cancel   context.CancelFunc
	done     chan error
	// wallOffset moves the manager's wall clock away from the virtual time; atomic because the test changes it while the manager runs.
	wallOffset atomic.Int64
}

func newHarness(t *testing.T, stateDir string, fake *fakeAuthority) *harness {
	t.Helper()
	h := &harness{t: t, stateDir: stateDir, fake: fake, logs: &logBuffer{}}
	m, err := newManager(managerConfig(stateDir, h.logs), fake)
	if err != nil {
		t.Fatal(err)
	}
	m.wall = func() time.Time { return time.Now().Add(time.Duration(h.wallOffset.Load())) }
	h.m = m
	t.Cleanup(func() {
		h.stop()
		if t.Failed() {
			t.Logf("log of the manager:\n%s", h.logs)
		}
	})
	return h
}

// run starts Run, or loop with pass when one is given.
func (h *harness) run(pass func(context.Context) time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() {
		// A panic that escapes Run would take the DNS server down with it; here it fails the test instead of the whole test binary.
		defer func() {
			if value := recover(); value != nil {
				h.t.Errorf("a panic escaped Run: %v", value)
				h.done <- nil
			}
		}()
		if pass == nil {
			h.done <- h.m.Run(ctx)
			return
		}
		h.done <- h.m.loop(ctx, pass)
	}()
}

// stop cancels Run and waits for it; a Run that does not return deadlocks the bubble, which fails the test.
func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	if err := <-h.done; err != nil {
		h.t.Errorf("Run returned %v, want nil", err)
	}
}

func (h *harness) returned() bool {
	select {
	case err := <-h.done:
		h.done <- err
		return true
	default:
		return false
	}
}

// at lets virtual time run until the given number of seconds after the start, and returns once the manager has done what was due then.
func (h *harness) at(s int) {
	h.t.Helper()
	if d := time.Until(h.fake.start.Add(time.Duration(s) * time.Second)); d > 0 {
		time.Sleep(d)
	}
	synctest.Wait()
}

func (h *harness) expectIssued(id string, want ...int) {
	h.t.Helper()
	if got := h.fake.issued(id); !slices.Equal(got, want) {
		h.t.Errorf("orders for %q at %v seconds, want %v", id, got, want)
	}
}

// logLine is one line of the manager's log, decoded.
type logLine map[string]any

func (b *logBuffer) lines() []logLine {
	var lines []logLine
	for line := range strings.SplitSeq(b.String(), "\n") {
		var decoded logLine
		if json.Unmarshal([]byte(line), &decoded) == nil {
			lines = append(lines, decoded)
		}
	}
	return lines
}

// find returns the lines with the level and message whose fields have the given values.
func (b *logBuffer) find(level, message string, fields map[string]any) []logLine {
	var found []logLine
	for _, line := range b.lines() {
		if line["level"] != level || line["message"] != message {
			continue
		}
		matches := true
		for key, value := range fields {
			if line[key] != value {
				matches = false
			}
		}
		if matches {
			found = append(found, line)
		}
	}
	return found
}

func (b *logBuffer) errorLines() []logLine {
	var found []logLine
	for _, line := range b.lines() {
		if level := line["level"]; level == "error" || level == "fatal" || level == "panic" {
			found = append(found, line)
		}
	}
	return found
}

func sameLeaf(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Raw, b.Raw)
}

func leafOf(c *Certificate) *x509.Certificate {
	if c == nil {
		return nil
	}
	return c.TLS.Leaf
}

func assertStored(t *testing.T, stateDir, id string, names []string, want *Certificate) {
	t.Helper()
	stored, err := storeFor(t, stateDir).loadCertificate(id, names)
	if err != nil {
		t.Errorf("loading the stored %s certificate: %v", id, err)
		return
	}
	if want == nil || !bytes.Equal(stored.ChainPEM, want.ChainPEM) || !bytes.Equal(stored.KeyPEM, want.KeyPEM) {
		t.Errorf("the stored %s certificate is not the published one", id)
	}
}

func TestOrdersMissingCertificatesSiteFirst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		h := newHarness(t, t.TempDir(), fake)
		if h.m.Site() != nil || h.m.Wildcard() != nil {
			t.Fatal("a certificate is published before anything was stored or ordered")
		}
		h.run(nil)
		h.at(1)
		calls := fake.calls()
		if len(calls) != 2 || calls[0].id != "site" || calls[0].at != 0 || calls[1].id != "wildcard" || calls[1].at != time.Second {
			t.Fatalf("orders = %+v, want site at 0 and wildcard at 1", calls)
		}
		for _, call := range calls {
			if call.replaces != nil {
				t.Errorf("the order for %s carries replaces", call.id)
			}
		}
		if h.m.Site() == nil || h.m.Wildcard() == nil {
			t.Fatal("both certificates should be published")
		}
		if !slices.Equal(h.m.Site().TLS.Leaf.DNSNames, siteNames) || !slices.Equal(h.m.Wildcard().TLS.Leaf.DNSNames, wildcardNames) {
			t.Error("the published certificates do not have the expected names")
		}
		assertStored(t, h.stateDir, "site", siteNames, h.m.Site())
		assertStored(t, h.stateDir, "wildcard", wildcardNames, h.m.Wildcard())
		if len(h.logs.find("info", "Ordering certificate", map[string]any{"certificate": "site", "reason": "missing", "replaces": false})) != 1 {
			t.Error("no Ordering certificate line for site with reason missing")
		}
		if len(h.logs.find("info", "Certificate issued", map[string]any{"certificate": "wildcard"})) != 1 {
			t.Error("no Certificate issued line for wildcard")
		}
		h.at(2 * 3600)
		h.expectIssued("", 0, 1)
	})
}

func TestLoadsStoredCertificatesWithoutAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		first := newHarness(t, stateDir, newFakeAuthority())
		first.run(nil)
		first.at(1)
		first.stop()
		site, wildcard := first.m.Site(), first.m.Wildcard()
		if site == nil || wildcard == nil {
			t.Fatal("the first manager did not obtain both certificates")
		}

		down := errors.New("connection refused")
		fake := newFakeAuthority()
		fake.onIssue = func(context.Context, issueCall) error { return down }
		fake.onRenewalInfo = func(context.Context, infoCall) (renewalInfo, bool, error) { return renewalInfo{}, false, down }
		second := newHarness(t, stateDir, fake)
		if !sameLeaf(leafOf(second.m.Site()), site.TLS.Leaf) || !sameLeaf(leafOf(second.m.Wildcard()), wildcard.TLS.Leaf) {
			t.Fatal("the second manager does not publish the stored certificates before Run")
		}
		if n := len(second.logs.find("info", "Loaded stored certificate", nil)); n != 2 {
			t.Errorf("%d Loaded stored certificate lines, want 2", n)
		}
		second.run(nil)
		second.at(24 * 3600)
		second.expectIssued("")
		if !sameLeaf(leafOf(second.m.Site()), site.TLS.Leaf) || !sameLeaf(leafOf(second.m.Wildcard()), wildcard.TLS.Leaf) {
			t.Error("the stored certificates are no longer published")
		}
	})
}

func TestIgnoresUnusableStoredCertificate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		storeCertificate(t, stateDir, "site", freshCertificate(t, []string{"other.example"}))
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		h := newHarness(t, stateDir, fake)
		if h.m.Site() != nil {
			t.Fatal("a stored certificate with other names is published")
		}
		if len(h.logs.find("warn", "Ignoring stored certificate", map[string]any{"certificate": "site", "path": h.m.store.certificatePath("site")})) != 1 {
			t.Error("no Ignoring stored certificate warning with the path")
		}
		h.run(nil)
		h.at(10)
		h.expectIssued("site", 0)
		h.expectIssued("wildcard")
		if len(h.logs.find("info", "Ordering certificate", map[string]any{"certificate": "site", "reason": "missing"})) != 1 {
			t.Error("site was not ordered as missing")
		}
		assertStored(t, stateDir, "site", siteNames, h.m.Site())
	})
}

func TestRenewsWhenOneThirdOfLifetimeRemains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(1)
		site, wildcard := h.m.Site(), h.m.Wildcard()
		deadline := seconds(renewalAge)

		h.at(deadline - 1)
		h.expectIssued("", 0, 1)
		if h.m.Site() != site {
			t.Error("the first site certificate was not served until its deadline")
		}

		h.at(deadline)
		h.expectIssued("site", 0, deadline)
		calls := fake.calls()
		if last := calls[len(calls)-1]; !sameLeaf(last.replaces, site.TLS.Leaf) {
			t.Error("the renewal does not replace the published leaf")
		}
		if h.m.Site() == site || h.m.Site() == nil {
			t.Error("the renewed site certificate is not published")
		}
		if len(h.logs.find("info", "Ordering certificate", map[string]any{"certificate": "site", "reason": "lifetime", "replaces": true})) != 1 {
			t.Error("no Ordering certificate line with reason lifetime")
		}

		h.at(deadline + 1)
		h.expectIssued("wildcard", 1, deadline+1)
		if !sameLeaf(fake.calls()[3].replaces, wildcard.TLS.Leaf) {
			t.Error("the wildcard renewal does not replace the published leaf")
		}
	})
}

func TestRenewalInformationBringsRenewalForward(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const checkAfter = 6 * time.Hour
		fake := newFakeAuthority()
		fake.onRenewalInfo = func(_ context.Context, call infoCall) (renewalInfo, bool, error) {
			return renewalInfo{renewAt: call.leaf.NotBefore.Add(30 * day), checkAfter: checkAfter}, true, nil
		}
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		suggested := seconds(30 * day)

		h.at(3 * 3600 * 6)
		if got, want := fake.asked("site")[:3], []int{1, 1 + 6*3600, 1 + 12*3600}; !slices.Equal(got, want) {
			t.Errorf("renewal information for site asked at %v, want it first at %v", got, want)
		}

		h.at(suggested - 1)
		h.expectIssued("", 0, 1)
		h.at(suggested)
		h.expectIssued("site", 0, suggested)
		if len(h.logs.find("info", "Ordering certificate", map[string]any{"certificate": "site", "reason": "renewal information"})) != 1 {
			t.Error("no Ordering certificate line with reason renewal information")
		}
		h.at(suggested + 1)
		h.expectIssued("wildcard", 1, suggested+1)
	})
}

func TestRenewalInformationErrorsFallBackToLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		fake.onRenewalInfo = func(context.Context, infoCall) (renewalInfo, bool, error) {
			return renewalInfo{}, false, errors.New("the authority is down")
		}
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(3 * 3600)
		if got, want := fake.asked("site"), []int{1, 3601, 7201}; !slices.Equal(got, want) {
			t.Errorf("renewal information for site asked at %v, want %v", got, want)
		}
		if len(h.logs.find("warn", "Could not get renewal information", map[string]any{"certificate": "site"})) == 0 {
			t.Error("no warning about the failed request")
		}
		deadline := seconds(renewalAge)
		h.at(deadline - 1)
		h.expectIssued("", 0, 1)
		h.at(deadline + 1)
		h.expectIssued("", 0, 1, deadline, deadline+1)
	})
}

func TestAuthorityWithoutRenewalInformation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(3 * 24 * 3600)
		if got, want := fake.asked("site"), []int{1, 1 + 24*3600, 1 + 48*3600}; !slices.Equal(got, want) {
			t.Errorf("renewal information for site asked at %v, want %v", got, want)
		}
		if got, want := fake.asked("wildcard"), []int{2, 2 + 24*3600, 2 + 48*3600}; !slices.Equal(got, want) {
			t.Errorf("renewal information for wildcard asked at %v, want %v", got, want)
		}
	})
}

func TestFailedOrdersBackOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		original := dueCertificate(t, siteNames)
		storeCertificate(t, stateDir, "site", original)
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		// The certificates it issues are past their deadline too, so that the next renewal follows as soon as the hold ends.
		fake.backdate = 80 * day
		fake.onIssue = func(_ context.Context, call issueCall) error {
			if call.nth == 9 {
				return nil
			}
			return errors.New("connection refused")
		}
		h := newHarness(t, stateDir, fake)
		h.run(nil)

		attempts := []int{0, 300, 900, 2100, 4500, 9300, 18900, 40500, 62100}
		for i, at := range attempts[:8] {
			h.at(at)
			if !sameLeaf(leafOf(h.m.Site()), original.TLS.Leaf) {
				t.Fatalf("the published certificate changed after failure %d", i+1)
			}
		}
		h.at(62099)
		h.expectIssued("site", attempts[:8]...)
		h.at(62100)
		h.expectIssued("site", attempts...)
		for _, call := range fake.calls() {
			if !sameLeaf(call.replaces, original.TLS.Leaf) {
				t.Errorf("attempt at %v does not replace the stored certificate", call.at)
			}
		}
		renewed := h.m.Site()
		if sameLeaf(leafOf(renewed), original.TLS.Leaf) {
			t.Fatal("the certificate obtained at the ninth attempt is not published")
		}
		failed := h.logs.find("error", "Certificate order failed", map[string]any{"certificate": "site", "failures": float64(8)})
		if len(failed) != 1 || failed[0]["retry_at"] == nil || failed[0]["error"] != "connection refused" {
			t.Errorf("the line of the eighth failure is %v", failed)
		}

		// The new certificate is held back for an hour, then fails: the series starts again at 5 minutes.
		h.at(62100 + 3600 + 300)
		h.expectIssued("site", append(slices.Clone(attempts), 62100+3600, 62100+3600+300)...)
		if calls := fake.calls(); !sameLeaf(calls[len(calls)-1].replaces, renewed.TLS.Leaf) {
			t.Error("the attempt after the success does not replace the new certificate")
		}
		h.expectIssued("wildcard")
	})
}

func TestPauseStartsWhenTheOrderEnds(t *testing.T) {
	t.Run("failure", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
			fake := newFakeAuthority()
			fake.duration = 3 * time.Minute
			fake.onIssue = func(_ context.Context, call issueCall) error {
				if call.nth == 1 {
					return errors.New("timeout")
				}
				return nil
			}
			h := newHarness(t, stateDir, fake)
			h.run(nil)
			h.at(479)
			h.expectIssued("site", 0)
			h.at(480)
			h.expectIssued("site", 0, 480)
		})
	})
	t.Run("success", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
			fake := newFakeAuthority()
			fake.duration = 3 * time.Minute
			fake.backdate = 80 * day
			h := newHarness(t, stateDir, fake)
			h.run(nil)
			h.at(3779)
			h.expectIssued("site", 0)
			h.at(3780)
			h.expectIssued("site", 0, 3780)
		})
	})
}

func TestRefusalDropsReplaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		original := dueCertificate(t, siteNames)
		storeCertificate(t, stateDir, "site", original)
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		fake.backdate = 80 * day
		fake.onIssue = func(_ context.Context, call issueCall) error {
			switch call.nth {
			case 1:
				return fmt.Errorf("ordering: %w", acme.Problem{Type: acme.ProblemTypeUnauthorized, Detail: "not your certificate"})
			case 3:
				return fmt.Errorf("ordering: %w", acme.Problem{Type: acme.ProblemTypeRateLimited, Detail: "slow down"})
			}
			return nil
		}
		h := newHarness(t, stateDir, fake)
		h.run(nil)

		h.at(300)
		second := h.m.Site()
		h.at(300 + 3600 + 300)
		h.expectIssued("site", 0, 300, 3900, 4200)
		calls := fake.calls()
		if len(calls) != 4 {
			t.Fatalf("orders = %+v", calls)
		}
		if !sameLeaf(calls[0].replaces, original.TLS.Leaf) {
			t.Error("the first attempt does not replace the stored certificate")
		}
		if calls[1].replaces != nil {
			t.Error("the attempt after a refusal still carries replaces")
		}
		if !sameLeaf(calls[2].replaces, second.TLS.Leaf) {
			t.Error("the renewal after the success does not carry replaces again")
		}
		if !sameLeaf(calls[3].replaces, second.TLS.Leaf) {
			t.Error("the attempt after a rate limit does not keep replaces")
		}
		if len(h.logs.find("error", "Certificate order failed", map[string]any{"problem_type": acme.ProblemTypeUnauthorized, "problem_detail": "not your certificate"})) != 1 {
			t.Error("no Certificate order failed line with the problem's type and detail")
		}
	})
}

func TestFailingCertificateDoesNotStarveTheOther(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		fake.onIssue = func(_ context.Context, call issueCall) error {
			if call.id == "site" {
				return errors.New("validation failed")
			}
			return nil
		}
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(299)
		if h.m.Wildcard() != nil {
			t.Error("wildcard was published during the pause")
		}
		h.at(300)
		if h.m.Wildcard() == nil {
			t.Error("wildcard was not published after the pause")
		}
		h.at(2401)
		calls := fake.calls()
		var got []string
		for _, call := range calls {
			got = append(got, call.id+"@"+secondsOf(call.at))
		}
		want := []string{"site@0", "wildcard@300", "site@301", "site@601", "site@1201", "site@2401"}
		if !slices.Equal(got, want) {
			t.Errorf("orders = %v, want %v", got, want)
		}
	})
}

func TestRenewNow(t *testing.T) {
	t.Run("neither due", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			site, wildcard := freshCertificate(t, siteNames), freshCertificate(t, wildcardNames)
			storeCertificate(t, stateDir, "site", site)
			storeCertificate(t, stateDir, "wildcard", wildcard)
			fake := newFakeAuthority()
			h := newHarness(t, stateDir, fake)
			h.run(nil)
			h.at(100)
			h.expectIssued("")
			h.m.RenewNow()
			h.at(101)
			calls := fake.calls()
			if len(calls) != 2 || calls[0].id != "site" || seconds(calls[0].at) != 100 || calls[1].id != "wildcard" || seconds(calls[1].at) != 101 {
				t.Fatalf("orders = %+v, want site at 100 and wildcard at 101", calls)
			}
			if !sameLeaf(calls[0].replaces, site.TLS.Leaf) || !sameLeaf(calls[1].replaces, wildcard.TLS.Leaf) {
				t.Error("the requested renewals do not replace the published certificates")
			}
			if len(h.logs.find("info", "Ordering certificate", map[string]any{"reason": "requested", "replaces": true})) != 2 {
				t.Error("the orders are not logged with reason requested")
			}
			h.at(24 * 3600)
			h.expectIssued("", 100, 101)
		})
	})
	t.Run("during a pause", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
			storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
			fake := newFakeAuthority()
			fake.onIssue = func(_ context.Context, call issueCall) error {
				if call.nth == 1 && call.id == "site" {
					return errors.New("timeout")
				}
				return nil
			}
			h := newHarness(t, stateDir, fake)
			h.run(nil)
			h.at(100)
			h.m.RenewNow()
			h.at(200)
			h.expectIssued("", 100)
			h.m.RenewNow()
			h.at(201)
			var got []string
			for _, call := range fake.calls() {
				got = append(got, call.id+"@"+secondsOf(call.at))
			}
			if want := []string{"site@100", "wildcard@200", "site@201"}; !slices.Equal(got, want) {
				t.Errorf("orders = %v, want %v", got, want)
			}
		})
	})
	t.Run("twice before Run", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
			storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
			fake := newFakeAuthority()
			h := newHarness(t, stateDir, fake)
			h.m.RenewNow()
			h.m.RenewNow()
			h.run(nil)
			h.at(24 * 3600)
			h.expectIssued("site", 0)
			h.expectIssued("wildcard", 1)
		})
	})
}

func TestAuthorityRetryAfterIsHonoured(t *testing.T) {
	t.Run("orders", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeAuthority()
			fake.until = time.Now().Add(3 * time.Hour)
			h := newHarness(t, t.TempDir(), fake)
			h.run(nil)
			h.at(5400)
			h.m.RenewNow()
			h.at(10799)
			h.expectIssued("")
			if asked := fake.asked(""); len(asked) != 0 {
				t.Errorf("renewal information asked at %v during the wait", asked)
			}
			h.at(10801)
			h.expectIssued("site", 10800)
			h.expectIssued("wildcard", 10801)
		})
	})
	t.Run("renewal information", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stateDir := t.TempDir()
			storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
			storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
			fake := newFakeAuthority()
			var refused atomic.Bool
			fake.onRenewalInfo = func(context.Context, infoCall) (renewalInfo, bool, error) {
				if refused.CompareAndSwap(false, true) {
					fake.set(func(f *fakeAuthority) { f.until = time.Now().Add(3 * time.Hour) })
					return renewalInfo{}, false, errors.New("429 too many requests")
				}
				return renewalInfo{}, false, nil
			}
			h := newHarness(t, stateDir, fake)
			h.m.RenewNow()
			h.run(nil)
			h.at(10799)
			if got := fake.asked(""); !slices.Equal(got, []int{0}) {
				t.Errorf("renewal information asked at %v, want only the first request at 0", got)
			}
			h.expectIssued("")
			h.at(10801)
			if got := fake.asked("wildcard"); len(got) == 0 || got[0] != 10800 {
				t.Errorf("renewal information for wildcard asked at %v, want first at 10800", got)
			}
			h.expectIssued("site", 10800)
			h.expectIssued("wildcard", 10801)
		})
	})
}

func TestFreshCertificateIsNotRenewedAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		fake.backdate = 80 * day
		h := newHarness(t, t.TempDir(), fake)

		var (
			mu     sync.Mutex
			passes int
			// afterIssuance holds what automaticRenewal said right after each issuance.
			afterIssuance []string
		)
		h.run(func(ctx context.Context) time.Duration {
			wait := h.m.pass(ctx)
			mu.Lock()
			defer mu.Unlock()
			passes++
			for _, c := range h.m.certificates() {
				if c.issuedAt.Equal(time.Now()) {
					due, _, until := h.m.automaticRenewal(c)
					afterIssuance = append(afterIssuance, fmt.Sprintf("%s due=%v wait=%v", c.id, due, until))
				}
			}
			return wait
		})

		h.at(10*3600 - 1)
		var site, wildcard []int
		for hour := range 10 {
			site = append(site, hour*3600)
			wildcard = append(wildcard, hour*3600+1)
		}
		h.expectIssued("site", site...)
		h.expectIssued("wildcard", wildcard...)
		mu.Lock()
		if passes >= 100 {
			t.Errorf("%d passes in ten hours, want fewer than 100", passes)
		}
		if len(afterIssuance) != 20 {
			t.Errorf("%d issuances inspected, want 20", len(afterIssuance))
		}
		for _, said := range afterIssuance {
			if !strings.HasSuffix(said, "due=false wait=1h0m0s") {
				t.Errorf("right after an issuance automaticRenewal said %q, want not due for an hour", said)
			}
		}
		mu.Unlock()

		h.at(10*3600 + 1800)
		h.m.RenewNow()
		h.at(10*3600 + 1801)
		h.expectIssued("site", append(site, 10*3600, 10*3600+1800)...)
		h.expectIssued("wildcard", append(wildcard, 10*3600+1, 10*3600+1801)...)
	})
}

func TestMinimumIntervalIsElapsedTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(1)
		h.wallOffset.Store(int64(100 * day))

		h.at(3599)
		h.expectIssued("", 0, 1)
		h.at(3*3600 + 1)
		h.expectIssued("site", 0, 3600, 7200, 10800)
		h.expectIssued("wildcard", 1, 3601, 7201, 10801)

		h.at(3*3600 + 100)
		h.wallOffset.Store(0)
		realDeadline := 10800 + seconds(renewalAge)
		h.at(realDeadline - 1)
		h.expectIssued("site", 0, 3600, 7200, 10800)
		h.expectIssued("wildcard", 1, 3601, 7201, 10801)
		h.at(realDeadline + 1)
		h.expectIssued("site", 0, 3600, 7200, 10800, realDeadline)
		h.expectIssued("wildcard", 1, 3601, 7201, 10801, realDeadline+1)
	})
}

func TestWallClockJumpIsNoticedWithinTheHour(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(1000)
		h.wallOffset.Store(int64(61 * day))
		h.at(1000 + 3600)
		site := fake.issued("site")
		if len(site) != 2 || site[1] <= 1000 || site[1] > 1000+3600 {
			t.Errorf("site ordered at %v, want a second order within the hour after 1000", site)
		}
		if wildcard := fake.issued("wildcard"); len(wildcard) != 2 || wildcard[1] > 1000+3600 {
			t.Errorf("wildcard ordered at %v, want a second order within the hour after 1000", wildcard)
		}
	})
}

func TestStoreFailureKeepsServingFromMemory(t *testing.T) {
	skipWithoutPermissions(t)
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		h := newHarness(t, stateDir, fake)
		domainDir := h.m.store.domainDir
		t.Cleanup(func() { _ = os.Chmod(domainDir, 0o700) })
		h.run(nil)

		h.at(10)
		oldSite, oldWildcard := h.m.Site(), h.m.Wildcard()
		if err := os.Chmod(domainDir, 0o500); err != nil {
			t.Fatal(err)
		}
		h.m.RenewNow()
		h.at(11)
		h.expectIssued("", 10, 11)
		if len(h.logs.find("error", "Could not store certificate, serving it from memory", map[string]any{"certificate": "site"})) != 1 {
			t.Error("no error line for the failed write of site")
		}
		site, wildcard := h.m.Site(), h.m.Wildcard()
		if leafOf(site) == nil || sameLeaf(leafOf(site), leafOf(oldSite)) {
			t.Fatal("the new site certificate is not published while the store cannot be written")
		}
		if leafOf(wildcard) == nil || sameLeaf(leafOf(wildcard), leafOf(oldWildcard)) {
			t.Fatal("the new wildcard certificate is not published while the store cannot be written")
		}
		assertStored(t, stateDir, "site", siteNames, oldSite)
		assertStored(t, stateDir, "wildcard", wildcardNames, oldWildcard)

		h.at(10 + 5*60)
		if n := len(h.logs.find("error", "Could not store certificate, serving it from memory", map[string]any{"certificate": "site"})); n != 6 {
			t.Errorf("%d failed writes of site after 5 minutes, want 6 (one a minute)", n)
		}
		if err := os.Chmod(domainDir, 0o700); err != nil {
			t.Fatal(err)
		}
		h.at(10 + 6*60 + 1)
		h.expectIssued("", 10, 11)
		if h.m.Site() != site || h.m.Wildcard() != wildcard {
			t.Error("the published certificates changed")
		}
		assertStored(t, stateDir, "site", siteNames, site)
		assertStored(t, stateDir, "wildcard", wildcardNames, wildcard)
		if len(h.logs.find("info", "Stored certificate", map[string]any{"certificate": "site"})) != 1 {
			t.Error("no Stored certificate line for site")
		}
		h.at(24 * 3600)
		h.expectIssued("", 10, 11)
	})
}

func TestNewerCertificateIsNeverOverwrittenByAnOlderOne(t *testing.T) {
	skipWithoutPermissions(t)
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		h := newHarness(t, stateDir, fake)
		domainDir := h.m.store.domainDir
		t.Cleanup(func() { _ = os.Chmod(domainDir, 0o700) })
		h.run(nil)

		h.at(10)
		if err := os.Chmod(domainDir, 0o500); err != nil {
			t.Fatal(err)
		}
		h.m.RenewNow()
		h.at(11)
		older := h.m.Site()

		h.at(30)
		if err := os.Chmod(domainDir, 0o700); err != nil {
			t.Fatal(err)
		}
		h.m.RenewNow()
		h.at(31)
		h.expectIssued("", 10, 11, 30, 31)
		newer := h.m.Site()
		if newer == older {
			t.Fatal("the second requested renewal did not publish a new certificate")
		}

		h.at(30 + 10*60)
		assertStored(t, stateDir, "site", siteNames, newer)
		assertStored(t, stateDir, "wildcard", wildcardNames, h.m.Wildcard())
	})
}

func TestPanicsAreContained(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		fake.onIssue = func(_ context.Context, call issueCall) error {
			if call.id == "site" && call.nth == 1 {
				panic("the authority client is broken")
			}
			return nil
		}
		fake.onRenewalInfo = func(context.Context, infoCall) (renewalInfo, bool, error) {
			panic("renewal information is broken")
		}
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)

		h.at(301)
		var got []string
		for _, call := range fake.calls() {
			got = append(got, call.id+"@"+secondsOf(call.at))
		}
		if want := []string{"site@0", "wildcard@300", "site@301"}; !slices.Equal(got, want) {
			t.Errorf("orders = %v, want %v", got, want)
		}
		failed := h.logs.find("error", "Certificate order failed", map[string]any{"certificate": "site", "failures": float64(1)})
		if len(failed) != 1 || !strings.Contains(fmt.Sprint(failed[0]["error"]), "the authority client is broken") {
			t.Errorf("the panic did not count as a failed order: %v", failed)
		}

		wildcardDeadline := 300 + seconds(renewalAge)
		h.at(wildcardDeadline + 1)
		h.expectIssued("wildcard", 300, wildcardDeadline)
		h.expectIssued("site", 0, 301, wildcardDeadline+1)
		if len(fake.asked("")) == 0 {
			t.Error("renewal information was never asked for")
		}
		if h.returned() {
			t.Error("Run returned")
		}
	})
}

func TestLoopNeverSpins(t *testing.T) {
	t.Run("pass returns zero", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeAuthority()
			h := newHarness(t, t.TempDir(), fake)
			var (
				mu    sync.Mutex
				times []int
			)
			h.run(func(context.Context) time.Duration {
				mu.Lock()
				defer mu.Unlock()
				times = append(times, seconds(time.Since(fake.start)))
				return 0
			})
			h.at(10)
			h.m.RenewNow()
			h.at(10)
			h.stop()
			mu.Lock()
			defer mu.Unlock()
			if want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}; !slices.Equal(times, want) {
				t.Errorf("passes at %v, want %v", times, want)
			}
		})
	})
	t.Run("pass panics", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeAuthority()
			h := newHarness(t, t.TempDir(), fake)
			var (
				mu    sync.Mutex
				times []int
			)
			h.run(func(context.Context) time.Duration {
				mu.Lock()
				times = append(times, seconds(time.Since(fake.start)))
				mu.Unlock()
				panic("a bug in the scheduling")
			})
			h.at(100)
			h.m.RenewNow()
			h.at(1500)
			h.stop()
			mu.Lock()
			defer mu.Unlock()
			if want := []int{0, 300, 600, 900, 1200, 1500}; !slices.Equal(times, want) {
				t.Errorf("passes at %v, want %v", times, want)
			}
			if n := len(h.logs.find("error", "Certificate manager recovered from a panic", nil)); n != 6 {
				t.Errorf("%d recovery lines, want 6", n)
			}
		})
	})
}

const hostilePanicText = "the text of a hostile panic value"

// hostilePanic is a panic value that encoding/json cannot marshal without panicking itself.
type hostilePanic struct{}

func (hostilePanic) MarshalJSON() ([]byte, error) { panic("marshalling the panic value") }
func (hostilePanic) Error() string                { return hostilePanicText }

func TestPanicValuesAreLoggedAsText(t *testing.T) {
	t.Run("hostile value", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeAuthority()
			h := newHarness(t, t.TempDir(), fake)
			var passes atomic.Int64
			h.run(func(context.Context) time.Duration {
				passes.Add(1)
				panic(hostilePanic{})
			})
			h.at(600)
			if h.returned() {
				t.Fatal("loop returned")
			}
			if n := passes.Load(); n != 3 {
				t.Errorf("%d passes in 10 minutes, want 3 (one every 5 minutes)", n)
			}
			if n := len(h.logs.find("error", "Certificate manager recovered from a panic", map[string]any{"panic": hostilePanicText})); n != 3 {
				t.Errorf("%d recovery lines carrying %q, want 3", n, hostilePanicText)
			}
		})
	})
	t.Run("runtime error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeAuthority()
			h := newHarness(t, t.TempDir(), fake)
			outOfRange := 3
			h.run(func(context.Context) time.Duration {
				var empty []int
				return time.Duration(empty[outOfRange])
			})
			h.at(1)
			lines := h.logs.find("error", "Certificate manager recovered from a panic", nil)
			if len(lines) != 1 || !strings.Contains(fmt.Sprint(lines[0]["panic"]), "index out of range") {
				t.Errorf("recovery lines = %v, want the runtime error's message", lines)
			}
		})
	})
}

func TestGuard(t *testing.T) {
	logs := &logBuffer{}
	m, err := newManager(managerConfig(t.TempDir(), logs), newFakeAuthority())
	if err != nil {
		t.Fatal(err)
	}
	err = m.guard("doing the impossible", func() error { panic("the value of the panic") })
	if err == nil || !strings.Contains(err.Error(), "panic while doing the impossible") || !strings.Contains(err.Error(), "the value of the panic") {
		t.Errorf("err = %v, want one that names the operation and the panic value", err)
	}
	if lines := logs.errorLines(); len(lines) != 1 || lines[0]["stack"] == nil {
		t.Errorf("error lines = %v, want one with the stack", lines)
	}
	hostile := func() (err error) {
		defer func() {
			if value := recover(); value != nil {
				t.Errorf("a panic escaped guard: %v", value)
			}
		}()
		return m.guard("meeting a hostile value", func() error { panic(hostilePanic{}) })
	}()
	if hostile == nil || !strings.Contains(hostile.Error(), hostilePanicText) {
		t.Errorf("err = %v, want one that carries %q", hostile, hostilePanicText)
	}
	if lines := logs.errorLines(); len(lines) != 2 || lines[1]["panic"] != hostilePanicText {
		t.Errorf("error lines = %v, want a second one whose panic field is %q", lines, hostilePanicText)
	}

	plain := errors.New("plain failure")
	if err := m.guard("failing", func() error { return plain }); err != plain {
		t.Errorf("err = %v, want the function's error unchanged", err)
	}
	if err := m.guard("succeeding", func() error { return nil }); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if n := len(logs.errorLines()); n != 2 {
		t.Errorf("%d error lines, want still 2", n)
	}
}

func TestRunReturnsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeAuthority()
		blocked := make(chan struct{}, 1)
		fake.onIssue = func(ctx context.Context, _ issueCall) error {
			blocked <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}
		h := newHarness(t, t.TempDir(), fake)
		h.run(nil)
		h.at(10)
		select {
		case <-blocked:
		default:
			t.Fatal("the order did not start")
		}
		if h.returned() {
			t.Fatal("Run returned while the order was blocked")
		}
		h.stop()
		if lines := h.logs.errorLines(); len(lines) != 0 {
			t.Errorf("error lines after cancellation: %v", lines)
		}
	})
}

func TestRunReturnsDuringRenewalInformation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateDir := t.TempDir()
		storeCertificate(t, stateDir, "site", freshCertificate(t, siteNames))
		storeCertificate(t, stateDir, "wildcard", freshCertificate(t, wildcardNames))
		fake := newFakeAuthority()
		fake.onRenewalInfo = func(ctx context.Context, _ infoCall) (renewalInfo, bool, error) {
			<-ctx.Done()
			return renewalInfo{}, false, ctx.Err()
		}
		h := newHarness(t, stateDir, fake)
		h.run(nil)
		h.at(10)
		if got := fake.asked(""); !slices.Equal(got, []int{0}) {
			t.Fatalf("renewal information asked at %v, want one request blocked since 0", got)
		}
		h.stop()
		if got := fake.asked(""); len(got) != 1 {
			t.Errorf("renewal information asked at %v, want exactly one request", got)
		}
		for _, line := range h.logs.lines() {
			if level := line["level"]; level != "info" && level != "debug" && level != "trace" {
				t.Errorf("line at level %v after cancellation: %v", level, line)
			}
		}
	})
}

func TestManagerWithRealAuthority(t *testing.T) {
	env := newTestEnv(t)
	cfg := env.config(t)
	logs := &logBuffer{}
	cfg.Logger = zerolog.New(logs).Level(zerolog.InfoLevel)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log of the managers:\n%s", logs)
		}
	})

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	eventually(t, "both certificates are published", func() bool { return m.Site() != nil && m.Wildcard() != nil })
	verifyFor(t, m.Site(), testDomain, env.ca.IssuerRoots)
	verifyFor(t, m.Wildcard(), "anything."+testDomain, env.ca.IssuerRoots)
	firstSite, firstWildcard := m.Site().TLS.Leaf.SerialNumber, m.Wildcard().TLS.Leaf.SerialNumber

	m.RenewNow()
	eventually(t, "both serial numbers change", func() bool {
		return m.Site().TLS.Leaf.SerialNumber.Cmp(firstSite) != 0 && m.Wildcard().TLS.Leaf.SerialNumber.Cmp(firstWildcard) != 0
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	site, wildcard := m.Site(), m.Wildcard()
	if lines := logs.errorLines(); len(lines) != 0 {
		t.Errorf("error lines while the authority was up: %v", lines)
	}
	env.ca.Stop()

	restartLogs := &logBuffer{}
	cfg.Logger = zerolog.New(restartLogs).Level(zerolog.InfoLevel)
	restarted, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Site() == nil || restarted.Site().TLS.Leaf.SerialNumber.Cmp(site.TLS.Leaf.SerialNumber) != 0 {
		t.Error("the restarted manager does not publish the stored site certificate")
	}
	if restarted.Wildcard() == nil || restarted.Wildcard().TLS.Leaf.SerialNumber.Cmp(wildcard.TLS.Leaf.SerialNumber) != 0 {
		t.Error("the restarted manager does not publish the stored wildcard certificate")
	}
	runCtx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	if err := restarted.Run(runCtx); err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
	if lines := restartLogs.errorLines(); len(lines) != 0 {
		t.Errorf("error lines without an authority: %v", lines)
	}
	if t.Failed() {
		t.Logf("log of the restarted manager:\n%s", restartLogs)
	}
}

// eventually polls condition until it holds, and fails the test when it does not within a generous bound.
func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
