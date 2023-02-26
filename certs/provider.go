package certs

import (
	"github.com/go-acme/lego/v4/challenge/dns01"

	"local-ip.sh/xip"
)

type DNSProviderLocalIp struct {
	xip *xip.Xip
}

func (d *DNSProviderLocalIp) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	d.xip.SetTXTRecord(fqdn, value)
	return nil
}

func (d *DNSProviderLocalIp) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	d.xip.UnsetTXTRecord(fqdn)
	return nil
}

func newProviderLocalIp(xip *xip.Xip) *DNSProviderLocalIp {
	return &DNSProviderLocalIp{
		xip,
	}
}
