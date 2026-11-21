package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/urfave/negroni"
)

var flyRegion = os.Getenv("FLY_REGION")

const (
	shutdownTimeout   = 3 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 16

	notIssuedBody = "The certificate has not been issued yet. Try again in a minute.\n"
)

var errNoCertificate = errors.New("no certificate has been issued yet")

// Pair is the published wildcard certificate: the chain as issued, leaf first, and its private key, both PEM-encoded.
type Pair struct {
	CertificatePEM []byte
	KeyPEM         []byte
	// NotBefore is the leaf's start of validity; it is served as Last-Modified.
	NotBefore time.Time
}

// CertificateSource is read on every TLS handshake and on every request for the pair, so implementations must be cheap and safe for concurrent use.
type CertificateSource interface {
	// SiteCertificate returns the website's certificate, or nil while none has been issued.
	SiteCertificate() *tls.Certificate
	// PublishedPair returns the wildcard pair; ok is false while none has been issued.
	PublishedPair() (pair Pair, ok bool)
}

// Options configures a Server.
type Options struct {
	Certificates CertificateSource
	// StaticDir holds index.html, styles.css, og.png and favicon.ico.
	StaticDir string
	Logger    zerolog.Logger
}

// Server is the website on plain HTTP and HTTPS. It holds no certificate itself: every handshake and every request for the pair asks the CertificateSource.
type Server struct {
	certificates CertificateSource
	staticDir    string
	logger       zerolog.Logger
	site         http.Handler
}

// NewServer returns a Server that serves nothing until Run is called.
func NewServer(opts Options) *Server {
	s := &Server{
		certificates: opts.Certificates,
		staticDir:    opts.StaticDir,
		logger:       opts.Logger,
	}
	s.site = s.newSiteHandler()
	return s
}

// Run serves plain HTTP on httpListener and HTTPS on httpsListener until ctx is cancelled, then shuts both down and returns nil.
// It returns the first error of either server if one stops by itself. It takes ownership of both listeners and closes them in every case.
func (s *Server) Run(ctx context.Context, httpListener, httpsListener net.Listener) error {
	// http.Server closes a listener only once Serve has been reached with it, so closing here as well covers every early return.
	defer httpListener.Close()
	defer httpsListener.Close()

	httpsPort, err := listenerPort(httpsListener)
	if err != nil {
		return fmt.Errorf("read the HTTPS listener's port: %w", err)
	}

	httpServer := s.newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.certificates.SiteCertificate() == nil {
			s.site.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, redirectTarget(r.URL, r.Host, httpsPort), http.StatusMovedPermanently)
	}))
	httpsServer := s.newHTTPServer(s.site)
	httpsServer.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if certificate := s.certificates.SiteCertificate(); certificate != nil {
				return certificate, nil
			}
			return nil, errNoCertificate
		},
	}

	s.logger.Info().Str("http_address", httpListener.Addr().String()).Msg("Starting up HTTP server")
	s.logger.Info().Str("https_address", httpsListener.Addr().String()).Msg("Starting up HTTPS server")

	serveErrors := make(chan error, 2)
	var serving sync.WaitGroup
	serving.Go(func() {
		if err := httpServer.Serve(httpListener); err != nil {
			serveErrors <- fmt.Errorf("serve HTTP: %w", err)
		}
	})
	serving.Go(func() {
		if err := httpsServer.ServeTLS(httpsListener, "", ""); err != nil {
			serveErrors <- fmt.Errorf("serve HTTPS: %w", err)
		}
	})
	// Every return stops serving: a loop that ended by itself leaves the connections it already accepted open until its server is closed, and after a graceful shutdown closing again finds nothing left.
	defer func() {
		httpServer.Close()
		httpsServer.Close()
		serving.Wait()
	}()

	select {
	case <-ctx.Done():
		s.shutdown(httpServer, httpsServer)
		return nil
	case err := <-serveErrors:
		return err
	}
}

func (s *Server) shutdown(servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Go(func() {
			if err := server.Shutdown(ctx); err != nil {
				s.logger.Debug().Err(err).Msg("Closing connections that outlived the shutdown limit")
				server.Close()
			}
		})
	}
	wg.Wait()
}

func (s *Server) newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(debugWriter{logger: s.logger.With().Str("source", "net/http").Logger()}, "", 0),
	}
}

// debugWriter keeps net/http's own messages, mostly failed handshakes from scanners and every handshake before the first certificate, out of the default output.
type debugWriter struct {
	logger zerolog.Logger
}

func (w debugWriter) Write(p []byte) (int, error) {
	w.logger.Debug().Msg(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (s *Server) newSiteHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /server.key", s.servePublishedPair("server.key", "application/octet-stream", func(p Pair) []byte { return p.KeyPEM }))
	mux.HandleFunc("GET /server.pem", s.servePublishedPair("server.pem", "application/x-x509-ca-cert", func(p Pair) []byte { return p.CertificatePEM }))
	mux.HandleFunc("GET /og.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, filepath.Join(s.staticDir, "og.png"))
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, filepath.Join(s.staticDir, "favicon.ico"))
	})
	mux.HandleFunc("GET /styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, filepath.Join(s.staticDir, "styles.css"))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, filepath.Join(s.staticDir, "index.html"))
	})

	n := negroni.New(negroni.HandlerFunc(s.logRequest))
	n.UseHandler(mux)
	return n
}

func (s *Server) servePublishedPair(name, contentType string, half func(Pair) []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pair, ok := s.certificates.PublishedPair()
		if !ok {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, notIssuedBody)
			return
		}

		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, name, pair.NotBefore, bytes.NewReader(half(pair)))
	}
}

func (s *Server) logRequest(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()
	next(w, r)
	response := w.(negroni.ResponseWriter)
	logEvent := s.logger.Debug()
	if flyRegion != "" {
		logEvent.Str("FLY_REGION", flyRegion)
	}
	logEvent.Msgf("%s %s %d %s", r.Method, r.URL.Path, response.Status(), time.Since(start))
}

func listenerPort(listener net.Listener) (int, error) {
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, fmt.Errorf("split %q: %w", listener.Addr().String(), err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", port, err)
	}
	return number, nil
}

// redirectTarget returns the HTTPS address of a plain HTTP request: the request's host without its port, the HTTPS port only when it is not the default one, and the request's path and query unchanged.
func redirectTarget(requestURL *url.URL, requestHost string, httpsPort int) string {
	host := requestHost
	if hostWithoutPort, _, err := net.SplitHostPort(requestHost); err == nil {
		host = hostWithoutPort
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}

	if httpsPort != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(httpsPort))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	// Built from the path and query alone: a request line in absolute form would otherwise carry its user information into the Location header.
	target := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     requestURL.Path,
		RawPath:  requestURL.RawPath,
		RawQuery: requestURL.RawQuery,
	}
	return target.String()
}
