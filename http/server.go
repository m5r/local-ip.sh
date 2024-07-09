package http

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func ServeHttp() {
	waitForCertificate()

	go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL
		url.Host = r.Host
		url.Scheme = "https"
		http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
	}))

	http.HandleFunc("/server.key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, "/certs/wildcard/server.key")
	})
	http.HandleFunc("/server.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		http.ServeFile(w, r, "/certs/wildcard/server.pem")
	})
	http.HandleFunc("/og.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/og.png")
	})
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "./http/static/favicon.ico")
	})
	http.HandleFunc("/styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeFile(w, r, "./http/static/styles.css")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.ServeFile(w, r, "./http/static/index.html")
	})
	log.Printf("Serving HTTPS server on :443\n")
	http.ListenAndServeTLS(":443", "/certs/root/server.pem", "/certs/root/server.key", nil)
}

func waitForCertificate() {
	for {
		_, err := os.Stat("/certs/root/output.json")
		if err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatal(err)
		}
		break
	}
}
