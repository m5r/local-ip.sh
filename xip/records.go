package xip

import (
	"net"

	"github.com/miekg/dns"
)

type hardcodedRecord struct {
	A     []net.IP // => dns.A
	AAAA  []net.IP // => dns.AAAA
	TXT   []string // => dns.TXT
	MX    []*dns.MX
	CNAME []string // => dns.CNAME
	SRV   *dns.SRV
}

var hardcodedRecords = map[string]hardcodedRecord{
	// additional records I set up to host emails, feel free to change or remove them for your own needs
	"local-ip.sh.": {
		TXT: []string{"v=spf1 include:capsulecorp.dev ~all"},
		MX: []*dns.MX{
			{Preference: 10, Mx: "email.capsulecorp.dev."},
		},
	},
	"autodiscover.local-ip.sh.": {
		CNAME: []string{
			"email.capsulecorp.dev.",
		},
	},
	"_autodiscover._tcp.local-ip.sh.": {
		SRV: &dns.SRV{
			Priority: 0,
			Weight:   0,
			Port:     443,
			Target:   "email.capsulecorp.dev.",
		},
	},
	"autoconfig.local-ip.sh.": {
		CNAME: []string{
			"email.capsulecorp.dev.",
		},
	},
	"_dmarc.local-ip.sh.": {
		TXT: []string{"v=DMARC1; p=none; rua=mailto:postmaster@local-ip.sh; ruf=mailto:admin@local-ip.sh"},
	},
	"dkim._domainkey.local-ip.sh.": {
		TXT: []string{
			"v=DKIM1;k=rsa;t=s;s=email;p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMW6NFo34qzKRPbzK41GwbWncB8IDg1i2eA2VWznIVDmTzzsqILaBOGv2xokVpzZm0QRF9wSbeVUmvwEeQ7Z6wkfMjawenDEc3XxsNSvQUVBP6LU/xcm1zsR8wtD8r5J+Jm45pNFaateiM/kb/Eypp2ntdtd8CPsEgCEDpNb62LWdy0yzRdZ/M/fNn51UMN8hVFp4YfZngAt3bQwa6kPtgvTeqEbpNf5xanpDysNJt2S8zfqJMVGvnr8JaJiTv7ZlKMMp94aC5Ndcir1WbMyfmgSnGgemuCTVMWDGPJnXDi+8BQMH1b1hmTpWDiVdVlehyyWx5AfPrsWG9cEuDIfXwIDAQAB",
		},
	},
}
