// Package acmetest runs an ACME certificate authority (Pebble) and small DNS servers inside a test process, so that the tests of several packages can issue real certificates without a network.
package acmetest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/core"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

// Init sets the environment Pebble reads when it is constructed (no artificial delays, no rejected nonces, as little authorization reuse as it allows). Challenges are really validated over DNS whatever the caller's environment holds: a PEBBLE_VA_ALWAYS_VALID exported in the shell is overridden. Call it from TestMain.
func Init() {
	// Pebble reads these once, in its constructors, and t.Setenv would forbid t.Parallel in every test that starts a CA.
	environment := map[string]string{
		"PEBBLE_VA_NOSLEEP":      "1",
		"PEBBLE_VA_ALWAYS_VALID": "0",
		"PEBBLE_WFE_NONCEREJECT": "0",
		"PEBBLE_AUTHZREUSE":      "0",
	}
	for name, value := range environment {
		if err := os.Setenv(name, value); err != nil {
			panic(fmt.Sprintf("setting %s: %v", name, err))
		}
	}
}

// CA is a running Pebble. Forget must not be called while another goroutine uses IssuerRoots.
type CA struct {
	// DirectoryURL is the ACME directory.
	DirectoryURL string
	// APIRoots verifies the HTTPS endpoint of the directory (certs.Config.TrustedRoots).
	APIRoots *x509.CertPool
	// IssuerRoots verifies the certificates it issues.
	IssuerRoots *x509.CertPool

	dnsAddress    string
	shortValidity time.Duration
	server        *httptest.Server
	current       atomic.Pointer[pebble]
}

// pebble is one generation of the authority's state; Forget replaces it while the endpoint stays.
type pebble struct {
	acme       http.Handler
	management http.Handler
}

func newPebble(dnsAddress string, shortValidity time.Duration) (*pebble, *x509.Certificate) {
	logger := log.New(io.Discard, "", 0)
	store := db.NewMemoryStore()
	profiles := map[string]ca.Profile{
		// A validity of zero is Pebble's default of 90 days.
		"default": {Description: "90 days"},
		"short":   {Description: shortValidity.String(), ValidityPeriod: uint64(shortValidity / time.Second)},
	}
	// ca.New panics on an empty key algorithm: the "rsa" default is applied by Pebble's main, not by the package.
	authority := ca.New(logger, store, "", "rsa", 0, 1, profiles)
	validator := va.New(logger, 0, 0, true, dnsAddress, store)
	// wfe.New returns a value and its handlers have pointer receivers, so it has to live in a variable.
	frontEnd := wfe.New(logger, store, validator, authority, nil, true, false, 0, 0)
	return &pebble{acme: frontEnd.Handler(), management: frontEnd.ManagementHandler()}, authority.GetRootCert(0).Cert
}

// Start runs an ACME server that validates DNS-01 by asking dnsAddress over TCP (Pebble's only mode with a custom resolver). It offers two profiles: "default" (90 days) and "short" (shortValidity, in whole seconds, at least one). Pebble sets NotAfter to NotBefore plus the validity minus one second, both ends being inclusive. Every order must name a profile, because Pebble picks one at random for an order that names none. It stops with the test.
func Start(t testing.TB, dnsAddress string, shortValidity time.Duration) *CA {
	t.Helper()
	if shortValidity < time.Second {
		t.Fatalf("acmetest.Start: shortValidity %v is shorter than Pebble's resolution of one second", shortValidity)
	}
	authority := &CA{dnsAddress: dnsAddress, shortValidity: shortValidity, IssuerRoots: x509.NewCertPool()}
	first, root := newPebble(dnsAddress, shortValidity)
	authority.current.Store(first)
	authority.IssuerRoots.AddCert(root)

	// One server dispatches to the current generation, so that Forget keeps the address, the TLS certificate and the connections clients already hold: a restarted listener would reset those connections and make a client's next POST fail with a transport error instead of the authority's answer.
	authority.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authority.current.Load().acme.ServeHTTP(w, r)
	}))
	t.Cleanup(authority.Stop)

	authority.DirectoryURL = authority.server.URL + wfe.DirectoryPath
	authority.APIRoots = x509.NewCertPool()
	authority.APIRoots.AddCert(authority.server.Certificate())
	return authority
}

// Forget replaces the server by a new one at the same address that knows no account, order or certificate. The new server issues from new keys; their roots are added to IssuerRoots, which goes on verifying what was issued before. The endpoint keeps its TLS certificate, so APIRoots stays valid.
func (c *CA) Forget() {
	next, root := newPebble(c.dnsAddress, c.shortValidity)
	c.IssuerRoots.AddCert(root)
	c.current.Store(next)
}

// Stop closes the server; the address then refuses connections. It waits for requests in progress and may be called more than once.
func (c *CA) Stop() {
	c.server.Close()
}

// SuggestRenewal makes the server answer renewal-information requests for leaf with the window [start, end]. It must not run while the server answers a renewal-information request for the same certificate: Pebble reads the stored answer without holding its lock.
func (c *CA) SuggestRenewal(leaf *x509.Certificate, start, end time.Time) error {
	if leaf == nil {
		return errors.New("suggesting a renewal window: no certificate")
	}
	if !end.After(start) {
		return fmt.Errorf("suggesting a renewal window: end %v is not after start %v", end, start)
	}
	window, err := json.Marshal(core.RenewalInfo{SuggestedWindow: core.SuggestedWindow{Start: start.UTC(), End: end.UTC()}})
	if err != nil {
		return fmt.Errorf("encoding the renewal window: %w", err)
	}
	body, err := json.Marshal(struct {
		Certificate string
		ARIResponse string
	}{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		ARIResponse: string(window),
	})
	if err != nil {
		return fmt.Errorf("encoding the renewal window request: %w", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/set-renewal-info/", bytes.NewReader(body))
	request.Header.Set("User-Agent", "acmetest")
	response := httptest.NewRecorder()
	c.current.Load().management.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		return fmt.Errorf("setting the renewal window: status %d: %s", response.Code, strings.TrimSpace(response.Body.String()))
	}
	return nil
}

// ServeTXT answers TXT queries over TCP on a free loopback port from lookup, and returns the address. It is the DNS side for tests that have no real server. lookup receives the query name in lower case without its trailing dot (for example "_acme-challenge.example.com") and may be called from several goroutines at once. Every answer is authoritative with a TTL of zero; other query types get an empty answer.
func ServeTXT(t testing.TB, lookup func(name string) []string) (address string) {
	t.Helper()
	return serveTCP(t, dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		answer := new(dns.Msg)
		if len(query.Question) != 1 {
			_ = w.WriteMsg(answer.SetRcode(query, dns.RcodeFormatError))
			return
		}
		answer.SetReply(query)
		answer.Authoritative = true
		question := query.Question[0]
		if question.Qtype == dns.TypeTXT && question.Qclass == dns.ClassINET {
			for _, value := range lookup(strings.ToLower(strings.TrimSuffix(question.Name, "."))) {
				answer.Answer = append(answer.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: splitTXT(value),
				})
			}
		}
		_ = w.WriteMsg(answer)
	}))
}

// splitTXT cuts a value into the 255-byte strings a TXT record is made of; Pebble joins them back.
func splitTXT(value string) []string {
	const maxString = 255
	var parts []string
	for len(value) > maxString {
		parts = append(parts, value[:maxString])
		value = value[maxString:]
	}
	return append(parts, value)
}

// Forwarder serves DNS over TCP on a loopback port and relays every query over UDP to a target that is set later. Pebble only asks a custom resolver over TCP and the server under test only listens on UDP; the target is set later because the server needs the directory URL before it binds its port. A UDP answer is relayed as it is, truncated or not.
type Forwarder struct {
	// Address is the TCP address to give to Start.
	Address string

	target atomic.Pointer[string]
}

// NewForwarder starts a Forwarder that stops with the test.
func NewForwarder(t testing.TB) *Forwarder {
	t.Helper()
	f := &Forwarder{}
	f.Address = serveTCP(t, dns.HandlerFunc(f.relay))
	return f
}

// SetTarget sets the UDP address queries are relayed to. Until it is called every query is answered with SERVFAIL.
func (f *Forwarder) SetTarget(udpAddress string) {
	f.target.Store(&udpAddress)
}

// relayTimeout stays under the 2 seconds Pebble's DNS client waits for an answer, so that a lost datagram gives Pebble a SERVFAIL rather than its own timeout.
const relayTimeout = time.Second

func (f *Forwarder) relay(w dns.ResponseWriter, query *dns.Msg) {
	target := f.target.Load()
	if target == nil {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(query, dns.RcodeServerFailure))
		return
	}
	client := &dns.Client{Net: "udp", Timeout: relayTimeout}
	answer, _, err := client.Exchange(query, *target)
	if err != nil {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(query, dns.RcodeServerFailure))
		return
	}
	_ = w.WriteMsg(answer)
}

// serveTCP returns only once the server accepts connections, and its cleanup waits for the serving goroutine, so that nothing outlives the test.
func serveTCP(t testing.TB, handler dns.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for DNS over TCP: %v", err)
	}
	started := make(chan struct{})
	server := &dns.Server{Listener: listener, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("serving DNS over TCP: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("stopping the DNS server at %s: %v", listener.Addr(), err)
		}
		<-done
	})
	return listener.Addr().String()
}
