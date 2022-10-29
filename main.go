package main

import (
	"flag"
	"strings"

	xip "local-ip.sh/xip"
)

const (
	zone        = "local-ip.sh."
	nameservers = "ns1.local-ip.sh.,ns2.local-ip.sh."
)

func main() {
	var port = flag.Int("port", 53, "port the DNS server should bind to")
	flag.Parse()

	n := xip.NewXip(zone, strings.Split(nameservers, ","), *port)
	n.StartServer()
}
