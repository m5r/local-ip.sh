package certs

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"github.com/rs/zerolog"
)

const (
	// minimumPassInterval is the shortest time between the end of a pass and the start of the next. A mistake in the rules can then cost one cheap pass a second and never a processor, which on a machine with a CPU allowance would mean throttled DNS.
	minimumPassInterval = time.Second
	// panicPause follows a pass that panicked: a bug in the scheduling must not be retried at the pace of ordinary passes.
	panicPause = 5 * time.Minute
	// maximumWait bounds the time between two passes. Wall-clock deadlines are waited for with timers, which do not follow the wall clock, so the decision is taken again at least every hour.
	maximumWait = time.Hour
	// minimumRenewalInterval holds back the automatic renewal of a certificate this process obtained. A wall clock that runs ahead, or renewal information that asks for every new certificate to be replaced at once, would otherwise turn each success into the next order, and an hour changes nothing for a real renewal, which comes days or weeks after the issuance.
	minimumRenewalInterval = time.Hour

	saveRetryInterval          = time.Minute
	renewalInfoErrorInterval   = time.Hour
	withoutRenewalInfoInterval = 24 * time.Hour
)

// Manager keeps the certificate for the domain and the one for its wildcard issued, renewed and stored. Site and Wildcard may be called from any goroutine; everything else it holds belongs to the goroutine that runs Run.
type Manager struct {
	logger zerolog.Logger
	store  *store
	ca     authority
	// wall reads the wall clock, against which certificate validity and the authority's suggested renewal time are compared. It is time.Now outside tests.
	wall func() time.Time
	// renew carries RenewNow's request to the loop; its capacity of one makes requests that arrive before the loop takes them count once.
	renew chan struct{}

	site, wildcard certificateState

	failures   int
	pauseUntil time.Time
}

// certificateState is one certificate with what the manager knows about it. Every moment in it is elapsed time, compared with time.Now.
type certificateState struct {
	id        string
	names     []string
	published atomic.Pointer[Certificate]

	lastAttempt     time.Time
	issuedAt        time.Time
	requested       bool
	withoutReplaces bool
	renewal         *renewalInfo
	infoCheckAt     time.Time
	unsaved         bool
	saveRetryAt     time.Time
}

// NewManager checks cfg and loads the stored certificates. It never contacts the authority, and a state directory that cannot be read is a warning, not an error.
func NewManager(cfg Config) (*Manager, error) {
	checked, err := checkConfig(cfg)
	if err != nil {
		return nil, err
	}
	ca, err := newACMEAuthority(checked)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	return newManager(checked, ca)
}

func newManager(cfg Config, ca authority) (*Manager, error) {
	cfg, err := checkConfig(cfg)
	if err != nil {
		return nil, err
	}
	st, err := newStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	m := &Manager{
		logger:   cfg.Logger,
		store:    st,
		ca:       ca,
		wall:     time.Now,
		renew:    make(chan struct{}, 1),
		site:     certificateState{id: "site", names: []string{cfg.Domain}},
		wildcard: certificateState{id: "wildcard", names: []string{"*." + cfg.Domain}},
	}
	for _, c := range m.certificates() {
		m.load(c)
	}
	return m, nil
}

func (m *Manager) load(c *certificateState) {
	var loaded *Certificate
	err := m.guard("loading certificate "+c.id, func() error {
		var err error
		loaded, err = m.store.loadCertificate(c.id, c.names)
		return err
	})
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		m.logger.Warn().Str("certificate", c.id).Str("path", m.store.certificatePath(c.id)).Err(err).Msg("Ignoring stored certificate")
	default:
		c.published.Store(loaded)
		leaf := loaded.TLS.Leaf
		m.logger.Info().Str("certificate", c.id).Str("serial", leaf.SerialNumber.Text(16)).Time("not_after", leaf.NotAfter).Msg("Loaded stored certificate")
	}
}

// Run keeps both certificates issued and renewed until ctx is cancelled, then returns nil. No failure makes it return.
func (m *Manager) Run(ctx context.Context) error {
	return m.loop(ctx, m.pass)
}

// RenewNow asks for both certificates to be renewed without waiting for their time. It never blocks and may be called from any goroutine, before or during Run.
func (m *Manager) RenewNow() {
	select {
	case m.renew <- struct{}{}:
	default:
	}
}

// Site returns the certificate for Domain; nil while there is none. It is safe for concurrent use and costs one atomic load.
func (m *Manager) Site() *Certificate {
	return m.site.published.Load()
}

// Wildcard returns the certificate for *.Domain; nil while there is none. It is safe for concurrent use and costs one atomic load.
func (m *Manager) Wildcard() *Certificate {
	return m.wildcard.published.Load()
}

// certificates lists the two certificates in the order that breaks ties: site first.
func (m *Manager) certificates() [2]*certificateState {
	return [2]*certificateState{&m.site, &m.wildcard}
}

// loop runs pass until ctx is cancelled. It takes the pass as a parameter so that its safety net can be tested with a pass that misbehaves.
func (m *Manager) loop(ctx context.Context, pass func(context.Context) time.Duration) error {
	for {
		m.takeRenewRequest()
		wait, panicked := m.runPass(ctx, pass)
		if ctx.Err() != nil {
			return nil
		}
		ended := time.Now()
		if panicked {
			// Only cancellation ends this wait early: a pass that panics on a request would otherwise panic at the pace of the requests.
			if !sleep(ctx, panicPause) {
				return nil
			}
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		case <-m.renew:
			timer.Stop()
			m.requestRenewal()
		}
		if !sleep(ctx, minimumPassInterval-time.Since(ended)) {
			return nil
		}
	}
}

// runPass recovers a panic of the pass, because the DNS server shares the process and must outlive a bug here. The value is logged as text: fmt contains a panic raised by the value's own methods, where a JSON encoding would let it escape this recovery, and it keeps the message of an error with unexported fields.
func (m *Manager) runPass(ctx context.Context, pass func(context.Context) time.Duration) (wait time.Duration, panicked bool) {
	defer func() {
		if value := recover(); value != nil {
			m.logger.Error().Str("panic", fmt.Sprint(value)).Str("stack", string(debug.Stack())).Msg("Certificate manager recovered from a panic")
			panicked = true
		}
	}()
	return pass(ctx), false
}

// sleep waits for d and reports false when ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// takeRenewRequest lets a request that arrived before Run, or during the pause after a panic, be served by the pass about to start rather than one interval later.
func (m *Manager) takeRenewRequest() {
	select {
	case <-m.renew:
		m.requestRenewal()
	default:
	}
}

// requestRenewal keeps failures, so that a new failure continues the series, but ends our own pause: an operator's request is not held back by it. What the authority asked for with Retry-After is not ours to waive, and the request stays recorded until it can be served.
func (m *Manager) requestRenewal() {
	m.site.requested = true
	m.wildcard.requested = true
	m.pauseUntil = time.Time{}
}

// guard turns a panic of f into an error, so that a panic in the store or the authority follows that operation's ordinary failure path instead of cutting the pass short.
func (m *Manager) guard(operation string, f func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			m.logger.Error().Str("operation", operation).Str("panic", fmt.Sprint(value)).Str("stack", string(debug.Stack())).Msg("Recovered from a panic in the certificate manager")
			err = fmt.Errorf("panic while %s: %v", operation, value)
		}
	}()
	return f()
}

// automaticRenewal reports whether c is due for a renewal nobody asked for, and why. When it is not, wait is how long until it can be, and is positive. c must be published. It is the only place that takes this decision, so that the decision and the wait can never disagree.
func (m *Manager) automaticRenewal(c *certificateState) (due bool, reason string, wait time.Duration) {
	leaf := c.published.Load().TLS.Leaf
	deadline, reason := renewalDeadline(leaf), "lifetime"
	if c.renewal != nil && c.renewal.renewAt.Before(deadline) {
		deadline, reason = c.renewal.renewAt, "renewal information"
	}
	untilDeadline := deadline.Sub(m.wall())
	var untilReleased time.Duration
	// A certificate loaded from the store has a zero issuedAt and is never held back.
	if !c.issuedAt.IsZero() {
		untilReleased = time.Until(c.issuedAt.Add(minimumRenewalInterval))
	}
	if untilDeadline <= 0 && untilReleased <= 0 {
		return true, reason, 0
	}
	return false, "", max(untilDeadline, untilReleased)
}

// pass does what can be done now and returns how long to wait before the next pass.
func (m *Manager) pass(ctx context.Context) time.Duration {
	for _, c := range m.certificates() {
		if c.unsaved && !time.Now().Before(c.saveRetryAt) {
			m.retrySave(c)
		}
	}

	for _, c := range m.certificates() {
		if !m.refreshRenewalInfo(ctx, c) {
			return 0
		}
	}

	var (
		due     [2]bool
		reasons [2]string
		waits   [2]time.Duration
	)
	anyDue := false
	for i, c := range m.certificates() {
		switch {
		case c.published.Load() == nil:
			due[i], reasons[i] = true, "missing"
		case c.requested:
			due[i], reasons[i] = true, "requested"
		default:
			due[i], reasons[i], waits[i] = m.automaticRenewal(c)
		}
		anyDue = anyDue || due[i]
	}

	// Orders are strictly sequential: both certificates are validated at the same record name and share the authority's budget of failed validations.
	if anyDue && !time.Now().Before(m.pauseUntil) && !time.Now().Before(m.ca.waitUntil()) {
		chosen := -1
		for i, c := range m.certificates() {
			if due[i] && (chosen < 0 || c.lastAttempt.Before(m.certificates()[chosen].lastAttempt)) {
				chosen = i
			}
		}
		m.order(ctx, m.certificates()[chosen], reasons[chosen])
		// The other certificate may be due.
		return 0
	}

	wait := maximumWait
	if anyDue {
		wait = min(wait, time.Until(later(m.pauseUntil, m.ca.waitUntil())))
	}
	for i, c := range m.certificates() {
		if c.unsaved {
			wait = min(wait, time.Until(c.saveRetryAt))
		}
		if c.published.Load() == nil {
			continue
		}
		wait = min(wait, time.Until(later(c.infoCheckAt, m.ca.waitUntil())))
		if !due[i] {
			wait = min(wait, waits[i])
		}
	}
	return wait
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (m *Manager) retrySave(c *certificateState) {
	published := c.published.Load()
	err := m.guard("storing certificate "+c.id, func() error { return m.store.saveCertificate(c.id, published) })
	if err != nil {
		c.saveRetryAt = time.Now().Add(saveRetryInterval)
		m.logger.Error().Str("certificate", c.id).Err(err).Time("retry_at", c.saveRetryAt).Msg("Could not store certificate, serving it from memory")
		return
	}
	c.unsaved = false
	m.logger.Info().Str("certificate", c.id).Str("path", m.store.certificatePath(c.id)).Msg("Stored certificate")
}

// refreshRenewalInfo asks the authority for c's renewal information when it is time, and reports false when ctx was cancelled during the request. Renewal information is advisory: a failure keeps what was known.
func (m *Manager) refreshRenewalInfo(ctx context.Context, c *certificateState) bool {
	published := c.published.Load()
	if published == nil || time.Now().Before(c.infoCheckAt) {
		return true
	}
	// Looked at before each request: the answer to the previous one can be the refusal that forbids this one.
	if time.Now().Before(m.ca.waitUntil()) {
		return true
	}
	var (
		info renewalInfo
		ok   bool
	)
	err := m.guard("getting renewal information for "+c.id, func() error {
		var err error
		info, ok, err = m.ca.renewalInfo(ctx, published.TLS.Leaf)
		return err
	})
	now := time.Now()
	switch {
	case err != nil && ctx.Err() != nil:
		return false
	case err != nil:
		c.infoCheckAt = now.Add(renewalInfoErrorInterval)
		m.logger.Warn().Str("certificate", c.id).Err(err).Msg("Could not get renewal information")
	case !ok:
		c.renewal = nil
		c.infoCheckAt = now.Add(withoutRenewalInfoInterval)
	default:
		c.renewal = &info
		c.infoCheckAt = now.Add(info.checkAfter)
	}
	return true
}

func (m *Manager) order(ctx context.Context, c *certificateState, reason string) {
	// Set before the order starts, so that even an order that ends in a panic has had its turn.
	c.lastAttempt = time.Now()
	var replaces *x509.Certificate
	if current := c.published.Load(); current != nil && !c.withoutReplaces {
		replaces = current.TLS.Leaf
	}
	m.logger.Info().Str("certificate", c.id).Str("reason", reason).Bool("replaces", replaces != nil).Msg("Ordering certificate")

	var (
		issued  *Certificate
		renewal *renewalInfo
	)
	err := m.guard("ordering certificate "+c.id, func() error {
		result, err := m.ca.issue(ctx, c.names, replaces)
		if err != nil {
			return err
		}
		if result == nil {
			return errors.New("ordering a certificate: the authority returned nothing")
		}
		issued, err = newCertificate(result.keyPEM, result.chainPEM, c.names)
		if err != nil {
			return fmt.Errorf("accepting the issued certificate: %w", err)
		}
		renewal = result.renewal
		return nil
	})
	returned := time.Now()

	if err != nil {
		if ctx.Err() != nil {
			return
		}
		m.failures++
		m.pauseUntil = returned.Add(pauseAfter(m.failures))
		event := m.logger.Error().Str("certificate", c.id).Str("reason", reason).Err(err)
		if problem, ok := problemOf(err); ok {
			event = event.Str("problem_type", problem.Type).Str("problem_detail", problem.Detail)
			// A refusal caused by replaces (a certificate the authority does not know, or one issued to another account) must never block a renewal, while a rate limit or an error without a problem document says nothing about that field.
			if problem.Type != acme.ProblemTypeRateLimited {
				c.withoutReplaces = true
			}
		}
		event.Int("failures", m.failures).Time("retry_at", later(m.pauseUntil, m.ca.waitUntil())).Msg("Certificate order failed")
		return
	}

	c.published.Store(issued)
	// The flag always describes the certificate published now, so an older certificate can never be written over a newer one.
	c.unsaved = false
	if err := m.guard("storing certificate "+c.id, func() error { return m.store.saveCertificate(c.id, issued) }); err != nil {
		c.unsaved = true
		c.saveRetryAt = time.Now().Add(saveRetryInterval)
		m.logger.Error().Str("certificate", c.id).Err(err).Time("retry_at", c.saveRetryAt).Msg("Could not store certificate, serving it from memory")
	} else {
		m.logger.Info().Str("certificate", c.id).Str("path", m.store.certificatePath(c.id)).Msg("Stored certificate")
	}
	c.issuedAt = returned
	m.failures = 0
	m.pauseUntil = time.Time{}
	c.requested = false
	c.withoutReplaces = false
	if renewal != nil {
		c.renewal = renewal
		c.infoCheckAt = time.Now().Add(renewal.checkAfter)
	} else {
		c.renewal = nil
		c.infoCheckAt = time.Now()
	}
	leaf := issued.TLS.Leaf
	m.logger.Info().Str("certificate", c.id).Str("serial", leaf.SerialNumber.Text(16)).Time("not_before", leaf.NotBefore).Time("not_after", leaf.NotAfter).Time("renew_by", renewalDeadline(leaf)).Msg("Certificate issued")
}
