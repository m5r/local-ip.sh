package main

import (
	"flag"
	"strings"

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

	// not functional yet
	/* go func() {
		account := certs.LoadAccount()
		log.Println(account.Registration.Body.Contact)
		ddd := certs.NewCertsClient(n, account)

		time.Sleep(5 * time.Second)
		fmt.Println("requesting certs")
		ddd.RequestCertificate()
	}() */

	n.StartServer()
}
