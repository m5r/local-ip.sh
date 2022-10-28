package main

import (
	"flag"
	"strings"

	xip "local-ip.dev/xip"
)

const (
	zone        = "my.local-ip.dev."
	nameservers = "ns.local-ip.dev."
)

func main() {
	var port = flag.Int("port", 53, "port the DNS server should bind to")
	flag.Parse()

	n := xip.NewXip(zone, strings.Split(nameservers, ","), *port)
	n.StartServer()
}
