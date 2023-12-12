package http

import (
	"net/http"
)

func ServeCertificate() {
	http.HandleFunc("/server.key", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/certs/server.key")
	})
	http.HandleFunc("/server.pem", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/certs/server.pem")
	})
	http.ListenAndServe(":9229", nil)
}
