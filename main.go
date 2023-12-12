package main

import (
	"flag"
	"strings"
	"time"

	"local-ip.sh/certs"
	"local-ip.sh/http"
	"local-ip.sh/xip"
)

const (
	zone        = "local-ip.sh."
	nameservers = "ns1.local-ip.sh.,ns2.local-ip.sh."
)

func main() {
	port := flag.Int("port", 53, "port the DNS server should bind to")
	flag.Parse()

	n := xip.NewXip(zone, strings.Split(nameservers, ","), *port)

	go func() {
		account := certs.LoadAccount()
		certsClient := certs.NewCertsClient(n, account)

		time.Sleep(5 * time.Second)
		certsClient.RequestCertificate()

		for {
			// try to renew certificate every day
			time.Sleep(24 * time.Hour)
			certsClient.RequestCertificate()
		}
	}()

	go http.ServeCertificate()

	n.StartServer()
}
