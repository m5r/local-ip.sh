package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"local-ip.sh/certs"
	"local-ip.sh/xip"
)

const (
	zone        = "local-ip.sh."
	nameservers = "ns1.local-ip.sh.,ns2.local-ip.sh."
)

func main() {
	var port = flag.Int("port", 53, "port the DNS server should bind to")
	flag.Parse()

	n := xip.NewXip(zone, strings.Split(nameservers, ","), *port)

	go func() {
		account := certs.LoadAccount()
		log.Println(account.Registration.Body.Contact)
		certsClient := certs.NewCertsClient(n, account)

		time.Sleep(5 * time.Second)
		certsClient.RequestCertificate()

		for {
			// renew certificate every month
			time.Sleep(30 * 24 * time.Hour)
			certsClient.RenewCertificate()
		}
	}()

	n.StartServer()
}
