package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	httpTimeout  = 15 * time.Second
	maxBodyBytes = 1 << 20
)

// pinnedClient sends every request to ip whatever the URL host, which stays the TLS server name
// and the verified name, so each nameserver's instance is checked on its own.
func pinnedClient(t *testing.T, tg *target, ip netip.Addr) *http.Client {
	t.Helper()
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("splitting dial address %q: %w", addr, err)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig: &tls.Config{RootCAs: tg.roots},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func get(t *testing.T, client *http.Client, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building request for %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		t.Fatalf("reading body of GET %s: %v", url, err)
	}
	return resp, body
}

func expectStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Errorf("GET %s: status = %d, want %d", resp.Request.URL, resp.StatusCode, want)
	}
}

func expectMediaType(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Errorf("GET %s: parsing Content-Type %q: %v", resp.Request.URL, contentType, err)
		return
	}
	if mediaType != want {
		t.Errorf("GET %s: media type = %q, want %q", resp.Request.URL, mediaType, want)
	}
}

func peerLeaf(t *testing.T, resp *http.Response) *x509.Certificate {
	t.Helper()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("GET %s: no peer certificate", resp.Request.URL)
	}
	return resp.TLS.PeerCertificates[0]
}

func website(t *testing.T, tg *target) {
	d := tg.domain
	for _, ip := range tg.nameServers {
		t.Run(ip.String(), func(t *testing.T) {
			client := pinnedClient(t, tg, ip)

			tests := []struct {
				name  string
				url   string
				check func(t *testing.T, resp *http.Response, body []byte)
			}{
				{name: "home page", url: "https://" + d + "/", check: func(t *testing.T, resp *http.Response, body []byte) {
					expectStatus(t, resp, http.StatusOK)
					expectMediaType(t, resp, "text/html")
					if !bytes.Contains(body, []byte("local-ip.sh")) {
						t.Error("body does not contain \"local-ip.sh\"")
					}
					if leaf := peerLeaf(t, resp); !slices.Equal(leaf.DNSNames, []string{d}) {
						t.Errorf("leaf DNSNames = %v, want [%s]", leaf.DNSNames, d)
					}
				}},
				{name: "http redirect", url: "http://" + d + "/some/path?q=1", check: func(t *testing.T, resp *http.Response, _ []byte) {
					expectStatus(t, resp, http.StatusMovedPermanently)
					want := "https://" + d + "/some/path?q=1"
					if got := resp.Header.Get("Location"); got != want {
						t.Errorf("Location = %q, want %q", got, want)
					}
				}},
				{name: "stylesheet", url: "https://" + d + "/styles.css", check: func(t *testing.T, resp *http.Response, _ []byte) {
					expectStatus(t, resp, http.StatusOK)
					expectMediaType(t, resp, "text/css")
				}},
				{name: "favicon", url: "https://" + d + "/favicon.ico", check: func(t *testing.T, resp *http.Response, _ []byte) {
					expectStatus(t, resp, http.StatusOK)
					expectMediaType(t, resp, "image/x-icon")
				}},
				{name: "open graph image", url: "https://" + d + "/og.png", check: func(t *testing.T, resp *http.Response, _ []byte) {
					expectStatus(t, resp, http.StatusOK)
					expectMediaType(t, resp, "image/png")
				}},
				{name: "missing page", url: "https://" + d + "/nope", check: func(t *testing.T, resp *http.Response, _ []byte) {
					expectStatus(t, resp, http.StatusNotFound)
				}},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					resp, body := get(t, client, tt.url)
					tt.check(t, resp, body)
				})
			}
		})
	}
}

// downloadPair fetches both published files. Status and media type are asserted on t; malformed
// content is returned as an error so that matchingKeyPair can tell it apart from a key mismatch.
func downloadPair(t *testing.T, client *http.Client, d string) (keyPair, error) {
	t.Helper()
	certURL := "https://" + d + "/server.pem"
	certResp, certPEM := get(t, client, certURL)
	expectStatus(t, certResp, http.StatusOK)
	expectMediaType(t, certResp, "application/x-x509-ca-cert")

	keyURL := "https://" + d + "/server.key"
	keyResp, keyPEM := get(t, client, keyURL)
	expectStatus(t, keyResp, http.StatusOK)
	expectMediaType(t, keyResp, "application/octet-stream")

	if t.Failed() {
		t.FailNow()
	}

	chain, err := parseChain(certPEM)
	if err != nil {
		return keyPair{}, fmt.Errorf("%s: %w", certURL, err)
	}
	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return keyPair{}, fmt.Errorf("%s: %w", keyURL, err)
	}
	return keyPair{chain: chain, signer: signer}, nil
}

func matchingPair(t *testing.T, client *http.Client, d string) keyPair {
	t.Helper()
	downloads := 0
	pair, err := matchingKeyPair(func() (keyPair, error) {
		downloads++
		if downloads > 1 {
			t.Log("published key does not match the published certificate; downloading both again in case a renewal replaced them in between")
		}
		return downloadPair(t, client, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func publicKeyDER(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("marshalling public key of %v: %v", cert.Subject, err)
	}
	return der
}

func wildcardCertificate(t *testing.T, tg *target) {
	d := tg.domain
	var firstPair *keyPair

	for i, ip := range tg.nameServers {
		t.Run(ip.String(), func(t *testing.T) {
			client := pinnedClient(t, tg, ip)
			pair := matchingPair(t, client, d)
			leaf := pair.leaf()

			if want := []string{"*." + d}; !slices.Equal(leaf.DNSNames, want) {
				t.Errorf("wildcard leaf DNSNames = %v, want %v", leaf.DNSNames, want)
			}

			if _, err := leaf.Verify(x509.VerifyOptions{
				DNSName:       "e2e." + d,
				Roots:         tg.roots,
				Intermediates: pair.intermediates(),
				CurrentTime:   time.Now(),
			}); err != nil {
				t.Errorf("wildcard leaf does not verify for e2e.%s: %v", d, err)
			}

			if err := leaf.VerifyHostname(d); err == nil {
				t.Errorf("wildcard leaf verifies for the apex %s, want an error", d)
			}

			resp, _ := get(t, client, "https://"+d+"/")
			if bytes.Equal(publicKeyDER(t, peerLeaf(t, resp)), publicKeyDER(t, leaf)) {
				t.Error("the website's certificate uses the published wildcard key")
			}

			if i == 0 {
				firstPair = &pair
			}
		})
	}

	t.Run("served from a LAN address", func(t *testing.T) {
		if firstPair == nil {
			t.Fatalf("no matching certificate and key were downloaded from %s", tg.nameServers[0])
		}
		lanRoundTrip(t, tg, *firstPair)
	})
}

// lanRoundTripHosts are the names through which lanRoundTrip reaches the published pair: the address alone, and a name in front of the address, the form the README recommends for HTTPS. Each is one label in front of the domain, the only names the wildcard certificate covers.
func lanRoundTripHosts(domain string) []string {
	return []string{"127-0-0-1." + domain, "e2e-app-127-0-0-1." + domain}
}

// lanRoundTrip serves the published pair on loopback and reaches it through the target's own DNS answer for each of lanRoundTripHosts, which is exactly how users are meant to use the wildcard certificate.
func lanRoundTrip(t *testing.T, tg *target, pair keyPair) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})},
		TLS: &tls.Config{Certificates: []tls.Certificate{pair.tlsCertificate()}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	loopback := netip.MustParseAddr("127.0.0.1")

	for _, host := range lanRoundTripHosts(tg.domain) {
		t.Run(host, func(t *testing.T) {
			addrs, err := lookupA(t, tg.nameServers[0], dns.Fqdn(host))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(addrs, []netip.Addr{loopback}) {
				t.Fatalf("%s A from %s = %v, want [%s]", host, tg.nameServers[0], addrs, loopback)
			}

			client := pinnedClient(t, tg, addrs[0])
			resp, _ := get(t, client, "https://"+net.JoinHostPort(host, port)+"/")
			expectStatus(t, resp, http.StatusOK)
		})
	}
}
