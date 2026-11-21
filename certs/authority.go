package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/rs/zerolog"

	"local-ip.sh/utils"
)

type authority interface {
	// issue orders a certificate for names with a fresh private key. replaces, when not nil, is the certificate the new one supersedes.
	issue(ctx context.Context, names []string, replaces *x509.Certificate) (*issuance, error)
	// renewalInfo asks the authority when leaf should be renewed. ok is false when it publishes no renewal information.
	renewalInfo(ctx context.Context, leaf *x509.Certificate) (info renewalInfo, ok bool, err error)
	// waitUntil is the moment before which the authority has asked not to be contacted, or the zero time when it has asked nothing or that moment has passed.
	waitUntil() time.Time
}

type issuance struct {
	keyPEM, chainPEM []byte
	// renewal is nil when the authority sent no renewal information with the certificate.
	renewal *renewalInfo
}

type renewalInfo struct {
	// renewAt is the moment chosen in the authority's suggested window, on the wall clock.
	renewAt time.Time
	// checkAfter is how long to wait before asking again.
	checkAfter time.Duration
}

const (
	issueTimeout       = 10 * time.Minute
	renewalInfoTimeout = time.Minute
	// httpTimeout bounds every request to the authority; the library sets no limit of its own.
	httpTimeout = 30 * time.Second

	defaultRenewalInfoInterval = 6 * time.Hour
	minimumRenewalInfoInterval = time.Minute
	maximumRenewalInfoInterval = 24 * time.Hour

	// maximumRetryAfter bounds what a wrong Retry-After header can cost; an authority that still refuses after it says so again.
	maximumRetryAfter = 24 * time.Hour
)

// acmeAuthority is the authority of the configuration, spoken to with acmez. Its issue calls are serialised; renewalInfo and waitUntil may run at any time.
type acmeAuthority struct {
	directoryURL string
	email        string
	profile      string
	store        *store
	logger       zerolog.Logger
	acmeLogger   *slog.Logger
	httpClient   *http.Client
	recorder     *retryAfterRecorder
	solver       *solver

	// mu is held for the whole of issue, which is the only user of account.
	mu sync.Mutex
	// account is the registered account, kept after an issue that succeeded and forgotten after any other, so that every attempt after a failure starts again from the key file.
	account *acme.Account
}

var _ authority = (*acmeAuthority)(nil)

// newACMEAuthority returns the authority of cfg, which must have gone through checkConfig. It contacts nothing: the directory is fetched by the first operation.
func newACMEAuthority(cfg Config) (*acmeAuthority, error) {
	st, err := newStore(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TrustedRoots != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: cfg.TrustedRoots}
	}
	recorder := &retryAfterRecorder{next: transport}
	return &acmeAuthority{
		directoryURL: cfg.DirectoryURL,
		email:        cfg.Email,
		profile:      cfg.Profile,
		store:        st,
		logger:       cfg.Logger,
		acmeLogger:   slog.New(utils.NewSlogHandler(cfg.Logger.With().Str("component", "acme").Logger())),
		httpClient:   &http.Client{Timeout: httpTimeout, Transport: recorder},
		recorder:     recorder,
		solver:       &solver{records: cfg.Records, delay: cfg.ValidationDelay},
	}, nil
}

// newClient returns a client for one operation. A client keeps the directory it fetched for its whole life, while new clients go through the library's process-wide cache, which refreshes it after 12 hours.
func (a *acmeAuthority) newClient() *acmez.Client {
	return &acmez.Client{
		Client: &acme.Client{
			Directory:  a.directoryURL,
			HTTPClient: a.httpClient,
			UserAgent:  "local-ip.sh",
			Logger:     a.acmeLogger,
		},
		ChallengeSolvers: map[string]acmez.Solver{acme.ChallengeTypeDNS01: a.solver},
	}
}

// issue returns a certificate that newCertificate accepts for names, or an error. When it fails because the authority refused, problemOf finds the authority's problem document in the error.
func (a *acmeAuthority) issue(ctx context.Context, names []string, replaces *x509.Certificate) (*issuance, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, issueTimeout)
	defer cancel()

	succeeded := false
	// Deferred so that a panic forgets the account too.
	defer func() {
		if !succeeded {
			a.account = nil
		}
	}()

	client := a.newClient()
	account, err := a.resolveAccount(ctx, client)
	if err != nil {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating the certificate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return nil, fmt.Errorf("creating the certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the certificate request: %w", err)
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		return nil, fmt.Errorf("preparing the order: %w", err)
	}
	params.Profile = a.profile
	params.Replaces = replaces

	chains, err := client.ObtainCertificate(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("obtaining a certificate for %q: %w", names, err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("obtaining a certificate for %q: the authority returned no chain", names)
	}
	chain := chains[0]
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := newCertificate(keyPEM, chain.ChainPEM, names); err != nil {
		return nil, fmt.Errorf("accepting the certificate for %q: %w", names, err)
	}
	result := &issuance{keyPEM: keyPEM, chainPEM: chain.ChainPEM}
	if chain.RenewalInfo != nil && chain.RenewalInfo.HasWindow() {
		info := convertRenewalInfo(*chain.RenewalInfo)
		result.renewal = &info
	}
	succeeded = true
	return result, nil
}

// resolveAccount returns the account kept in memory, or registers the stored key, which the authority answers with the existing account when it already knows the key (RFC 8555, section 7.3.1). Nothing but the key is stored, so there is no account URL that could be stale, missing or damaged.
func (a *acmeAuthority) resolveAccount(ctx context.Context, client *acmez.Client) (acme.Account, error) {
	if a.account != nil {
		return *a.account, nil
	}
	key, err := a.accountKey()
	if err != nil {
		return acme.Account{}, err
	}
	request := acme.Account{TermsOfServiceAgreed: true, PrivateKey: key}
	if a.email != "" {
		request.Contact = []string{"mailto:" + a.email}
	}
	account, err := client.NewAccount(ctx, request)
	if err != nil {
		return acme.Account{}, fmt.Errorf("registering the ACME account: %w", err)
	}
	// The library refuses to order with any other status, and an account the authority has deactivated or revoked is an operator's matter.
	if account.Status != acme.StatusValid {
		return acme.Account{}, fmt.Errorf("using the ACME account %s: its status is %q, not %q", account.Location, account.Status, acme.StatusValid)
	}
	a.logger.Info().Str("account", account.Location).Msg("ACME account ready")
	a.account = &account
	return account, nil
}

// accountKey loads the stored account key, or creates one and stores it before it is used, so that a key that cannot be stored is never registered and a process that keeps failing there cannot use up the authority's limit on new accounts.
func (a *acmeAuthority) accountKey() (*ecdsa.PrivateKey, error) {
	key, err := a.store.loadAccountKey()
	switch {
	case err == nil:
		return key, nil
	case errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, errUnusableAccountKey):
		a.logger.Warn().Err(err).Str("path", a.store.accountKeyPath()).Msg("Replacing unusable ACME account key")
	default:
		// The file may be fine: replacing it would lose the account for a passing error.
		return nil, fmt.Errorf("loading the ACME account key: %w", err)
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the ACME account key: %w", err)
	}
	if err := a.store.saveAccountKey(key); err != nil {
		return nil, fmt.Errorf("storing the ACME account key: %w", err)
	}
	return key, nil
}

func (a *acmeAuthority) renewalInfo(ctx context.Context, leaf *x509.Certificate) (renewalInfo, bool, error) {
	if leaf == nil {
		return renewalInfo{}, false, errors.New("getting renewal information: no certificate")
	}
	ctx, cancel := context.WithTimeout(ctx, renewalInfoTimeout)
	defer cancel()
	info, err := a.newClient().GetRenewalInfo(ctx, leaf)
	if errors.Is(err, acme.ErrUnsupported) {
		return renewalInfo{}, false, nil
	}
	if err != nil {
		return renewalInfo{}, false, fmt.Errorf("getting renewal information: %w", err)
	}
	if !info.HasWindow() {
		return renewalInfo{}, false, errors.New("getting renewal information: the answer has no window")
	}
	return convertRenewalInfo(info), true, nil
}

// waitUntil is the moment before which the authority has asked, with Retry-After on a refusal, not to be contacted. The manager starts no order and no request for renewal information before it. Inside an operation that is already running, the library's own bounded retries stay as they are: after a 5xx answer it repeats a request up to twice, a quarter of a second apart, and it asks for renewal information up to three times, 2 and 5 seconds apart, each time with those repeats.
func (a *acmeAuthority) waitUntil() time.Time {
	return a.recorder.waitUntil()
}

// convertRenewalInfo takes the library's selected time as it is and turns its absolute Retry-After into a delay.
func convertRenewalInfo(info acme.RenewalInfo) renewalInfo {
	checkAfter := defaultRenewalInfoInterval
	if info.RetryAfter != nil {
		checkAfter = time.Until(*info.RetryAfter)
	}
	checkAfter = min(max(checkAfter, minimumRenewalInfoInterval), maximumRenewalInfoInterval)
	return renewalInfo{renewAt: info.SelectedTime, checkAfter: checkAfter}
}

// problemOf finds the authority's problem document in err. The library returns problems as values in most paths and as a pointer, possibly a typed nil, when an order becomes invalid.
func problemOf(err error) (acme.Problem, bool) {
	var value acme.Problem
	if errors.As(err, &value) {
		return value, true
	}
	var pointer *acme.Problem
	if errors.As(err, &pointer) && pointer != nil {
		return *pointer, true
	}
	return acme.Problem{}, false
}

// retryAfterRecorder exists because the library does not hand the Retry-After header of a refused request to its caller. It is safe for concurrent use.
type retryAfterRecorder struct {
	next http.RoundTripper

	mu    sync.Mutex
	until time.Time
}

func (r *retryAfterRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.next.RoundTrip(request)
	if err != nil {
		return response, err
	}
	// On a 200 the header is a polling interval, which the library handles.
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		r.record(response.Header.Get("Retry-After"))
	}
	return response, err
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the transport underneath.
func (r *retryAfterRecorder) CloseIdleConnections() {
	if closer, ok := r.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// record keeps the moment header names, as elapsed time from now so that a correction of the wall clock changes nothing, at most maximumRetryAfter ahead and never earlier than a moment already recorded. A header that is neither a number of seconds nor an HTTP date is ignored.
func (r *retryAfterRecorder) record(header string) {
	now := time.Now()
	delay, ok := parseRetryAfter(header, now)
	if !ok {
		return
	}
	moment := now.Add(min(delay, maximumRetryAfter))
	r.mu.Lock()
	defer r.mu.Unlock()
	if moment.After(r.until) {
		r.until = moment
	}
}

func parseRetryAfter(header string, now time.Time) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if strings.Trim(header, "0123456789") == "" {
		seconds, err := strconv.ParseUint(header, 10, 64)
		if err != nil || seconds > uint64(maximumRetryAfter/time.Second) {
			// Only an overflow fails here, and it means at least the maximum.
			return maximumRetryAfter, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	date, err := http.ParseTime(header)
	if err != nil {
		return 0, false
	}
	return date.Sub(now), true
}

// waitUntil returns the recorded moment while it is ahead, and the zero time otherwise.
func (r *retryAfterRecorder) waitUntil() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.until) {
		return r.until
	}
	return time.Time{}
}
