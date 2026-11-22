package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rs/zerolog"
)

const testTimeout = 10 * time.Second

type fakeSource struct {
	mu      sync.Mutex
	site    *tls.Certificate
	pair    Pair
	hasPair bool
}

func (f *fakeSource) SiteCertificate() *tls.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.site
}

func (f *fakeSource) PublishedPair() (Pair, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pair, f.hasPair
}

func (f *fakeSource) setSite(certificate *tls.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.site = certificate
}

func (f *fakeSource) setPair(pair Pair) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pair = pair
	f.hasPair = true
}

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pool        *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "throw-away test CA"},
		NotBefore:             time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return &testCA{certificate: certificate, key: key, pool: pool}
}

type testLeaf struct {
	certificate    *x509.Certificate
	tls            *tls.Certificate
	certificatePEM []byte
	keyPEM         []byte
}

var serialNumber struct {
	mu   sync.Mutex
	next int64
}

func nextSerial() *big.Int {
	serialNumber.mu.Lock()
	defer serialNumber.mu.Unlock()
	serialNumber.next++
	return big.NewInt(1000 + serialNumber.next)
}

func (ca *testCA) issue(t *testing.T, dnsName string) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-30 * time.Minute).Truncate(time.Second),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf for %s: %v", dnsName, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf for %s: %v", dnsName, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Raw})...,
	)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatalf("load leaf for %s: %v", dnsName, err)
	}
	return &testLeaf{certificate: certificate, tls: &pair, certificatePEM: certificatePEM, keyPEM: keyPEM}
}

var staticFiles = map[string]string{
	"index.html":  "<!doctype html><title>index</title>\n",
	"styles.css":  "body { color: black; }\n",
	"og.png":      "not really a png\n",
	"favicon.ico": "not really an icon\n",
}

func testFiles() fstest.MapFS {
	files := fstest.MapFS{}
	for name, content := range staticFiles {
		files[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return files
}

type runningServer struct {
	httpAddr  string
	httpsAddr string
	cancel    context.CancelFunc
	done      chan error
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func startServer(t *testing.T, source CertificateSource) *runningServer {
	t.Helper()
	httpListener := listen(t)
	httpsListener := listen(t)
	server := NewServer(Options{
		Certificates: source,
		Files:        testFiles(),
		Logger:       zerolog.New(io.Discard),
	})
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningServer{
		httpAddr:  httpListener.Addr().String(),
		httpsAddr: httpsListener.Addr().String(),
		cancel:    cancel,
		done:      make(chan error, 1),
	}
	go func() { running.done <- server.Run(ctx, httpListener, httpsListener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-running.done:
			if err != nil {
				t.Errorf("Run returned %v after cancellation", err)
			}
		case <-time.After(testTimeout):
			t.Errorf("Run did not return within %s of cancellation", testTimeout)
		}
	})
	return running
}

func plainClient() *http.Client {
	return &http.Client{
		Timeout: testTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func tlsClient(ca *testCA, addr string) *http.Client {
	return &http.Client{
		Timeout: testTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: ca.pool, ServerName: "site.test"},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

type response struct {
	status int
	header http.Header
	body   []byte
	tls    *tls.ConnectionState
}

func get(t *testing.T, client *http.Client, rawURL string, header http.Header) response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request for %s: %v", rawURL, err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	if host := header.Get("Host"); host != "" {
		request.Host = host
	}
	resp, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", rawURL, err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: body, tls: resp.TLS}
}

func handshake(ca *testCA, addr string) (*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: testTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{RootCAs: ca.pool, ServerName: "site.test"})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}

func assertNotIssued(t *testing.T, r response, what string) {
	t.Helper()
	if r.status != http.StatusServiceUnavailable {
		t.Errorf("%s: status %d, want 503", what, r.status)
	}
	if got := r.header.Get("Retry-After"); got != "60" {
		t.Errorf("%s: Retry-After %q, want 60", what, got)
	}
	if got := r.header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("%s: Content-Type %q", what, got)
	}
	if string(r.body) != notIssuedBody {
		t.Errorf("%s: body %q", what, r.body)
	}
}

func TestBeforeAnyCertificate(t *testing.T) {
	ca := newTestCA(t)
	server := startServer(t, &fakeSource{})
	client := plainClient()
	base := "http://" + server.httpAddr

	index := get(t, client, base+"/", nil)
	if index.status != http.StatusOK || string(index.body) != staticFiles["index.html"] {
		t.Errorf("GET /: status %d body %q", index.status, index.body)
	}
	if got := index.header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("GET /: Content-Type %q", got)
	}

	assertNotIssued(t, get(t, client, base+"/server.pem", nil), "GET /server.pem")
	assertNotIssued(t, get(t, client, base+"/server.key", nil), "GET /server.key")

	if _, err := handshake(ca, server.httpsAddr); err == nil {
		t.Error("HTTPS handshake succeeded before any certificate was issued")
	}

	if notFound := get(t, client, base+"/nope", nil); notFound.status != http.StatusNotFound {
		t.Errorf("GET /nope: status %d, want 404", notFound.status)
	}
}

func TestSiteCertificateOnly(t *testing.T) {
	ca := newTestCA(t)
	site := ca.issue(t, "site.test")
	source := &fakeSource{}
	source.setSite(site.tls)
	server := startServer(t, source)

	_, httpsPort, err := net.SplitHostPort(server.httpsAddr)
	if err != nil {
		t.Fatalf("split %s: %v", server.httpsAddr, err)
	}
	redirect := get(t, plainClient(), "http://"+server.httpAddr+"/a/b?c=d", http.Header{"Host": {"site.test:8080"}})
	if redirect.status != http.StatusMovedPermanently {
		t.Errorf("HTTP GET /a/b?c=d: status %d, want 301", redirect.status)
	}
	if got, want := redirect.header.Get("Location"), "https://site.test:"+httpsPort+"/a/b?c=d"; got != want {
		t.Errorf("HTTP GET /a/b?c=d: Location %q, want %q", got, want)
	}

	client := tlsClient(ca, server.httpsAddr)
	index := get(t, client, "https://site.test/", nil)
	if index.status != http.StatusOK || string(index.body) != staticFiles["index.html"] {
		t.Errorf("HTTPS GET /: status %d body %q", index.status, index.body)
	}
	if index.tls == nil || !bytes.Equal(index.tls.PeerCertificates[0].Raw, site.certificate.Raw) {
		t.Error("HTTPS GET /: the peer certificate is not the site leaf")
	}

	assertNotIssued(t, get(t, client, "https://site.test/server.pem", nil), "HTTPS GET /server.pem")
}

func TestPublishedPair(t *testing.T) {
	ca := newTestCA(t)
	wildcard := ca.issue(t, "*.site.test")
	source := &fakeSource{}
	source.setPair(Pair{CertificatePEM: wildcard.certificatePEM, KeyPEM: wildcard.keyPEM, NotBefore: wildcard.certificate.NotBefore})
	server := startServer(t, source)
	client := plainClient()
	base := "http://" + server.httpAddr
	lastModified := wildcard.certificate.NotBefore.UTC().Format(http.TimeFormat)

	halves := []struct {
		path        string
		contentType string
		want        []byte
	}{
		{"/server.pem", "application/x-x509-ca-cert", wildcard.certificatePEM},
		{"/server.key", "application/octet-stream", wildcard.keyPEM},
	}
	downloaded := map[string][]byte{}
	for _, half := range halves {
		r := get(t, client, base+half.path, nil)
		if r.status != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", half.path, r.status)
		}
		if !bytes.Equal(r.body, half.want) {
			t.Errorf("GET %s: body differs from the pair", half.path)
		}
		if got := r.header.Get("Content-Type"); got != half.contentType {
			t.Errorf("GET %s: Content-Type %q, want %q", half.path, got, half.contentType)
		}
		if got := r.header.Get("Last-Modified"); got != lastModified {
			t.Errorf("GET %s: Last-Modified %q, want %q", half.path, got, lastModified)
		}
		downloaded[half.path] = r.body

		conditional := get(t, client, base+half.path, http.Header{"If-Modified-Since": {lastModified}})
		if conditional.status != http.StatusNotModified {
			t.Errorf("GET %s with If-Modified-Since: status %d, want 304", half.path, conditional.status)
		}
	}

	if _, err := tls.X509KeyPair(downloaded["/server.pem"], downloaded["/server.key"]); err != nil {
		t.Errorf("the downloaded pair does not load: %v", err)
	}
}

func TestCertificateSwap(t *testing.T) {
	ca := newTestCA(t)
	first := ca.issue(t, "site.test")
	second := ca.issue(t, "site.test")
	source := &fakeSource{}
	source.setSite(first.tls)
	server := startServer(t, source)

	presented, err := handshake(ca, server.httpsAddr)
	if err != nil {
		t.Fatalf("handshake with the first certificate: %v", err)
	}
	if !bytes.Equal(presented.Raw, first.certificate.Raw) {
		t.Fatal("the first handshake did not present the first certificate")
	}

	source.setSite(second.tls)
	presented, err = handshake(ca, server.httpsAddr)
	if err != nil {
		t.Fatalf("handshake after the swap on the same address %s: %v", server.httpsAddr, err)
	}
	if !bytes.Equal(presented.Raw, second.certificate.Raw) {
		t.Error("the handshake after the swap did not present the second certificate")
	}
}

func TestRedirectOmitsDefaultPort(t *testing.T) {
	requestURL := &url.URL{Path: "/a/b", RawQuery: "c=d"}
	cases := []struct {
		host      string
		httpsPort int
		want      string
	}{
		{"site.test", 443, "https://site.test/a/b?c=d"},
		{"site.test:80", 443, "https://site.test/a/b?c=d"},
		{"site.test", 8443, "https://site.test:8443/a/b?c=d"},
		{"site.test:8080", 8443, "https://site.test:8443/a/b?c=d"},
		{"[::1]", 443, "https://[::1]/a/b?c=d"},
		{"[::1]:80", 443, "https://[::1]/a/b?c=d"},
		{"[::1]", 8443, "https://[::1]:8443/a/b?c=d"},
		{"[::1]:8080", 8443, "https://[::1]:8443/a/b?c=d"},
	}
	for _, c := range cases {
		if got := redirectTarget(requestURL, c.host, c.httpsPort); got != c.want {
			t.Errorf("redirectTarget(%q, %d) = %q, want %q", c.host, c.httpsPort, got, c.want)
		}
	}
	if requestURL.Scheme != "" || requestURL.Host != "" {
		t.Errorf("redirectTarget changed the request's URL to %s", requestURL)
	}

	requestURLs := []struct {
		raw  string
		want string
	}{
		{"http://user:secret@site.test/a?b=c", "https://site.test/a?b=c"},
		{"/a%2Fb?c=d", "https://site.test/a%2Fb?c=d"},
		{"//other.test/x", "https://site.test//other.test/x"},
	}
	for _, c := range requestURLs {
		parsed, err := url.ParseRequestURI(c.raw)
		if err != nil {
			t.Fatalf("parse request URI %q: %v", c.raw, err)
		}
		got := redirectTarget(parsed, "site.test", 443)
		if got != c.want {
			t.Errorf("redirectTarget(%q) = %q, want %q", c.raw, got, c.want)
		}
		if target, err := url.Parse(got); err != nil || target.User != nil || target.Host != "site.test" {
			t.Errorf("redirectTarget(%q) = %q: want host site.test and no user information (parse error %v)", c.raw, got, err)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	httpListener := listen(t)
	httpsListener := listen(t)
	addrs := []string{httpListener.Addr().String(), httpsListener.Addr().String()}
	server := NewServer(Options{Certificates: &fakeSource{}, Files: testFiles(), Logger: zerolog.New(io.Discard)})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, httpListener, httpsListener) }()

	if r := get(t, plainClient(), "http://"+addrs[0]+"/", nil); r.status != http.StatusOK {
		t.Fatalf("GET / before cancellation: status %d", r.status)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatalf("Run did not return within %s of cancellation", testTimeout)
	}

	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("bind %s again after Run returned: %v", addr, err)
			continue
		}
		listener.Close()
	}
}

// keptConnection is a client connection on which one request has been answered and which the server would keep open for the next one.
type keptConnection struct {
	conn   net.Conn
	reader *bufio.Reader
}

func keepConnection(t *testing.T, conn net.Conn, what string) *keptConnection {
	t.Helper()
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("%s: set deadline: %v", what, err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n"); err != nil {
		t.Fatalf("%s: write request: %v", what, err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("%s: read response: %v", what, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("%s: read body: %v", what, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Close {
		t.Fatalf("%s: status %d, connection closing %v; want 200 on a connection kept open", what, resp.StatusCode, resp.Close)
	}
	return &keptConnection{conn: conn, reader: reader}
}

func (k *keptConnection) assertClosedByServer(t *testing.T, what string) {
	t.Helper()
	if err := k.conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("%s: set read deadline: %v", what, err)
	}
	buf := make([]byte, 1)
	n, err := k.reader.Read(buf)
	var netErr net.Error
	switch {
	case n > 0:
		t.Errorf("%s: the server sent data on the kept connection after Run returned", what)
	case errors.Is(err, io.EOF), errors.Is(err, syscall.ECONNRESET):
	case errors.As(err, &netErr) && netErr.Timeout():
		t.Errorf("%s: the kept connection is still open %s after Run returned", what, testTimeout)
	default:
		t.Errorf("%s: read on the kept connection: %v, want EOF or a reset", what, err)
	}
}

func TestRunReportsListenerError(t *testing.T) {
	for _, closed := range []string{"HTTP", "HTTPS"} {
		t.Run(closed+" listener closed", func(t *testing.T) {
			ca := newTestCA(t)
			source := &fakeSource{}
			httpListener := listen(t)
			httpsListener := listen(t)
			httpAddr := httpListener.Addr().String()
			httpsAddr := httpsListener.Addr().String()
			server := NewServer(Options{Certificates: source, Files: testFiles(), Logger: zerolog.New(io.Discard)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx, httpListener, httpsListener) }()

			plainConn, err := net.DialTimeout("tcp", httpAddr, testTimeout)
			if err != nil {
				t.Fatalf("dial %s: %v", httpAddr, err)
			}
			keptPlain := keepConnection(t, plainConn, "plain HTTP")
			// The site certificate is set only now so that the plain connection above was served the site rather than a redirect.
			source.setSite(ca.issue(t, "site.test").tls)
			tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: testTimeout}, "tcp", httpsAddr, &tls.Config{RootCAs: ca.pool, ServerName: "site.test"})
			if err != nil {
				t.Fatalf("TLS dial %s: %v", httpsAddr, err)
			}
			keptTLS := keepConnection(t, tlsConn, "HTTPS")

			closedListener, otherListener, otherAddr := httpListener, httpsListener, httpsAddr
			if closed == "HTTPS" {
				closedListener, otherListener, otherAddr = httpsListener, httpListener, httpAddr
			}
			closedListener.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("Run returned nil after its %s listener was closed from outside", closed)
				}
			case <-time.After(testTimeout):
				t.Fatalf("Run did not return within %s of its %s listener being closed", testTimeout, closed)
			}

			keptPlain.assertClosedByServer(t, "plain HTTP")
			keptTLS.assertClosedByServer(t, "HTTPS")

			if _, err := otherListener.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("Accept on the other listener after Run returned: %v, want net.ErrClosed", err)
			}
			listener, err := net.Listen("tcp", otherAddr)
			if err != nil {
				t.Fatalf("bind %s again after Run returned: %v", otherAddr, err)
			}
			listener.Close()
		})
	}
}

func TestRoutesServeTheEmbeddedFiles(t *testing.T) {
	server := NewServer(Options{Certificates: &fakeSource{}, Logger: zerolog.New(io.Discard)})
	routes := map[string]string{
		"/":            "index.html",
		"/styles.css":  "styles.css",
		"/og.png":      "og.png",
		"/favicon.ico": "favicon.ico",
	}
	for route, name := range routes {
		t.Run(route, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("static", name))
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			server.site.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200", route, recorder.Code)
			}
			if !bytes.Equal(recorder.Body.Bytes(), want) {
				t.Errorf("GET %s: the body is not the content of static/%s", route, name)
			}
		})
	}
}

func TestRequestLogCarriesTheRegion(t *testing.T) {
	for _, region := range []string{"ams", ""} {
		t.Run("region "+strconv.Quote(region), func(t *testing.T) {
			var buf bytes.Buffer
			server := NewServer(Options{Certificates: &fakeSource{}, Files: testFiles(), Region: region, Logger: zerolog.New(&buf).Level(zerolog.DebugLevel)})

			server.site.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("the log is not one JSON line: %v\n%s", err, buf.String())
			}
			got, present := line["FLY_REGION"]
			switch {
			case region == "" && present:
				t.Errorf("FLY_REGION = %v, want it absent", got)
			case region != "" && got != region:
				t.Errorf("FLY_REGION = %v, want %s", got, region)
			}
		})
	}
}

func TestRunCapsConnections(t *testing.T) {
	httpListener := listen(t)
	httpsListener := listen(t)
	httpAddr := httpListener.Addr().String()
	server := NewServer(Options{Certificates: &fakeSource{}, Files: testFiles(), Logger: zerolog.New(io.Discard)})
	server.maxConnections = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, httpListener, httpsListener) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	held, err := net.DialTimeout("tcp", httpAddr, testTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", httpAddr, err)
	}
	t.Cleanup(func() { held.Close() })
	keepConnection(t, held, "the connection at the cap")

	answered := make(chan error, 1)
	go func() {
		resp, err := plainClient().Get("http://" + httpAddr + "/")
		if err == nil {
			resp.Body.Close()
		}
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("a request beyond the cap ended with %v while the connection at the cap was open", err)
	case <-time.After(200 * time.Millisecond):
	}

	held.Close()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("the request beyond the cap failed after the connection at the cap closed: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("the request beyond the cap was not answered after the connection at the cap closed")
	}
}

func TestFilesAreRevalidatedByETag(t *testing.T) {
	server := NewServer(Options{Certificates: &fakeSource{}, Logger: zerolog.New(io.Discard)})
	for _, route := range []string{"/", "/styles.css", "/og.png", "/favicon.ico"} {
		t.Run(route, func(t *testing.T) {
			first := httptest.NewRecorder()
			server.site.ServeHTTP(first, httptest.NewRequest(http.MethodGet, route, nil))
			tag := first.Header().Get("ETag")
			if first.Code != http.StatusOK || len(tag) < 3 || tag[0] != '"' || tag[len(tag)-1] != '"' {
				t.Fatalf("GET %s: status %d, ETag %q; want 200 with a quoted strong tag", route, first.Code, tag)
			}

			request := httptest.NewRequest(http.MethodGet, route, nil)
			request.Header.Set("If-None-Match", tag)
			second := httptest.NewRecorder()
			server.site.ServeHTTP(second, request)
			if second.Code != http.StatusNotModified || second.Body.Len() != 0 {
				t.Errorf("GET %s with If-None-Match %s: status %d with %d octets of body, want 304 without a body", route, tag, second.Code, second.Body.Len())
			}
		})
	}
}

func TestETagFollowsTheContent(t *testing.T) {
	tagOf := func(content string) string {
		files := testFiles()
		files["styles.css"] = &fstest.MapFile{Data: []byte(content)}
		server := NewServer(Options{Certificates: &fakeSource{}, Files: files, Logger: zerolog.New(io.Discard)})
		recorder := httptest.NewRecorder()
		server.site.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/styles.css", nil))
		return recorder.Header().Get("ETag")
	}
	one, other := tagOf("body { color: black; }\n"), tagOf("body { color: white; }\n")
	if one == "" || one == other {
		t.Errorf("two contents got the tags %q and %q, want two different tags", one, other)
	}
}

func TestMissingFileIsNotFound(t *testing.T) {
	files := testFiles()
	delete(files, "styles.css")
	server := NewServer(Options{Certificates: &fakeSource{}, Files: files, Logger: zerolog.New(io.Discard)})
	recorder := httptest.NewRecorder()
	server.site.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/styles.css", nil))
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("ETag") != "" {
		t.Errorf("GET /styles.css without the file: status %d, ETag %q; want 404 without a tag", recorder.Code, recorder.Header().Get("ETag"))
	}
}
