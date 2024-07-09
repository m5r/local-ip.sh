package main

import (
	"flag"
	"time"

	"local-ip.sh/certs"
	"local-ip.sh/http"
	"local-ip.sh/xip"
)

func main() {
	port := flag.Int("port", 53, "port the DNS server should bind to")
	flag.Parse()

	n := xip.NewXip(*port)

	go func() {
		account := certs.LoadAccount()
		certsClient := certs.NewCertsClient(n, account)

		time.Sleep(5 * time.Second)
		certsClient.RequestCertificates()

		for {
			// try to renew certificate every day
			time.Sleep(24 * time.Hour)
			certsClient.RequestCertificates()
		}
	}()

	go http.ServeHttp()

	n.StartServer()
}
