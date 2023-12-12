package http

import (
	"log"
	"net/http"
)

func ServeCertificate() {
	http.HandleFunc("/server.key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, "/certs/server.key")
	})
	http.HandleFunc("/server.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		http.ServeFile(w, r, "/certs/server.pem")
	})
	log.Printf("Serving cert files on :9229\n")
	http.ListenAndServe(":9229", nil)
}
