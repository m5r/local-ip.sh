package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urfave/negroni"
	"local-ip.sh/utils"
)

var flyRegion = os.Getenv("FLY_REGION")

func loggingMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()
	next(w, r)
	response := w.(negroni.ResponseWriter)
	logEvent := utils.Logger.Debug()
	if flyRegion != "" {
		logEvent.Str("FLY_REGION", flyRegion)
	}
	logEvent.Msgf("%s %s %d %s", r.Method, r.URL.Path, response.Status(), time.Since(start))
}

func newHttpMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /server.key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, "./.lego/certs/wildcard/server.key")
	})
	mux.HandleFunc("GET /server.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		http.ServeFile(w, r, "./.lego/certs/wildcard/server.pem")
	})
	mux.HandleFunc("GET /og.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/og.png")
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/favicon.ico")
	})
	mux.HandleFunc("GET /styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, "./http/static/styles.css")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./http/static/index.html")
	})

	n := negroni.New(negroni.HandlerFunc(loggingMiddleware))
	n.UseHandler(mux)
	return n
}

func serveHttp() *http.Server {
	config := utils.GetConfig()
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.HttpPort),
		Handler: newHttpMux(),
	}
	utils.Logger.Info().Str("http_address", httpServer.Addr).Msg("Starting up HTTP server")
	go func() {
		err := httpServer.ListenAndServe()
		if err != http.ErrServerClosed {
			utils.Logger.Fatal().Err(err).Msg("Unexpected error received from HTTP server")
		}
	}()
	return httpServer
}

func waitForCertificate(ready chan bool) {
	for {
		_, err := os.Stat("./.lego/certs/root/output.json")
		if err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				time.Sleep(1 * time.Second)
				continue
			}
			utils.Logger.Fatal().Err(err).Msg("Unexpected error while looking for ./.lego/certs/root/output.json")
		}
		break
	}

	ready <- true
}

func killServer(httpServer *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := httpServer.Shutdown(ctx)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Unexpected error when shutting down HTTP server")
	}

	utils.Logger.Debug().Msg("HTTP server shut down correctly")
}

func redirectHttpToHttps() {
	config := utils.GetConfig()
	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", config.HttpPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			host := r.Host

			// Strip the port from the host if present
			if strings.Contains(host, ":") {
				hostWithoutPort, _, err := net.SplitHostPort(host)
				if err != nil {
					utils.Logger.Error().Err(err).Msg("Failed to split host and port")
				} else {
					host = hostWithoutPort
				}
			}
			// Add the HTTPS port only if it's not 443
			if config.HttpsPort != 443 {
				host = net.JoinHostPort(host, strconv.FormatUint(uint64(config.HttpsPort), 10))
			}

			url.Host = host
			url.Scheme = "https"
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
		}),
	}
	utils.Logger.Info().Str("http_address", httpServer.Addr).Msg("Redirecting HTTP traffic to HTTPS")
	go httpServer.ListenAndServe()
}

type CertificateReloader struct {
	CertificateFilePath string
	KeyFilePath         string
	mu                  sync.RWMutex
	certificate         *tls.Certificate
	lastUpdatedAt       time.Time
}

func (cr *CertificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	stat, err := os.Stat(cr.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed checking key file modification time: %w", err)
	}

	cr.mu.RLock()
	if cr.certificate != nil && !stat.ModTime().After(cr.lastUpdatedAt) {
		defer cr.mu.RUnlock()
		return cr.certificate, nil
	}
	cr.mu.RUnlock()

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if cr.certificate != nil && !stat.ModTime().After(cr.lastUpdatedAt) {
		return cr.certificate, nil
	}

	pair, err := tls.LoadX509KeyPair(cr.CertificateFilePath, cr.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed loading tls key pair: %w", err)
	}

	cr.certificate = &pair
	cr.lastUpdatedAt = stat.ModTime()
	return cr.certificate, nil
}

var certificateReloader = &CertificateReloader{
	CertificateFilePath: "./.lego/certs/root/server.pem",
	KeyFilePath:         "./.lego/certs/root/server.key",
}

func serveHttps() {
	config := utils.GetConfig()
	mux := newHttpMux()
	httpsServer := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.HttpsPort),
		Handler:   mux,
		TLSConfig: &tls.Config{GetCertificate: certificateReloader.GetCertificate},
	}
	utils.Logger.Info().Str("https_address", httpsServer.Addr).Msg("Starting up HTTPS server")
	go func() {
		err := httpsServer.ListenAndServeTLS("", "")
		if err != http.ErrServerClosed {
			utils.Logger.Fatal().Err(err).Msg("Unexpected error received from HTTPS server")
		}
	}()
}

func ServeHttp() {
	httpServer := serveHttp()

	ready := make(chan bool, 1)
	go waitForCertificate(ready)
	<-ready

	killServer(httpServer)

	serveHttps()
	redirectHttpToHttps()
}
