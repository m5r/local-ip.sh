package http

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"local-ip.sh/utils"
)

func registerHandlers() {
	http.HandleFunc("GET /server.key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, "./.lego/certs/wildcard/server.key")
	})
	http.HandleFunc("GET /server.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		http.ServeFile(w, r, "./.lego/certs/wildcard/server.pem")
	})
	http.HandleFunc("GET /og.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/og.png")
	})
	http.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/favicon.ico")
	})
	http.HandleFunc("GET /styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, "./http/static/styles.css")
	})
	http.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./http/static/index.html")
	})
}

func serveHttp() *http.Server {
	utils.Logger.Info().Msg("Starting up HTTP server on :80")
	httpServer := &http.Server{Addr: ":http"}
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
	utils.Logger.Info().Msg("Redirecting HTTP traffic from :80 to HTTPS :443")
	httpServer := &http.Server{
		Addr: ":http",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			url.Host = r.Host
			url.Scheme = "https"
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
		}),
	}
	go httpServer.ListenAndServe()
}

func serveHttps() {
	utils.Logger.Info().Msg("Starting up HTTPS server on :443")
	httpsServer := &http.Server{Addr: ":https"}
	go httpsServer.ListenAndServeTLS("./.lego/certs/root/server.pem", "./.lego/certs/root/server.key")
}

func ServeHttp() {
	registerHandlers()

	httpServer := serveHttp()

	ready := make(chan bool, 1)
	go waitForCertificate(ready)
	<-ready

	killServer(httpServer)

	serveHttps()
	redirectHttpToHttps()
}
