package certs

import (
	"fmt"
	"log"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"local-ip.sh/xip"
)

type certsClient struct {
	legoClient *lego.Client
}

func (c *certsClient) RequestCertificate() {
	certificates, err := c.legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{"*.local-ip.sh"},
		Bundle:  true,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%#v\n", certificates)
}

func NewCertsClient(xip *xip.Xip, user *Account) *certsClient {
	config := lego.NewConfig(user)
	config.CADirURL = caDirUrl
	legoClient, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	provider := newProviderLocalIp(xip)
	legoClient.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}))

	return &certsClient{
		legoClient,
	}
}
