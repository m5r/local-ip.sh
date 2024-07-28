package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"local-ip.sh/utils"
)

func newHttpMux() *http.ServeMux {
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

	return mux
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

			url.Host = r.Host
			url.Scheme = "https"
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
		}),
	}
	utils.Logger.Info().Str("http_address", httpServer.Addr).Msg("Redirecting HTTP traffic to HTTPS")
	go httpServer.ListenAndServe()
}

func serveHttps() {
	config := utils.GetConfig()
	mux := newHttpMux()
	httpsServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.HttpsPort),
		Handler: mux,
	}
	utils.Logger.Info().Str("https_address", httpsServer.Addr).Msg("Starting up HTTPS server")
	go httpsServer.ListenAndServeTLS("./.lego/certs/root/server.pem", "./.lego/certs/root/server.key")
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
