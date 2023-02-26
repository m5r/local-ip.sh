package certs

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"local-ip.sh/xip"
)

type certsClient struct {
	legoClient      *lego.Client
	lastCertificate *certificate.Resource
}

func (c *certsClient) RequestCertificate() {
	log.Println("requesting a certificate")
	if c.lastCertificate != nil {
		c.RenewCertificate()
		return
	}

	certificates, err := c.legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{"*.local-ip.sh"},
		Bundle:  true,
	})
	if err != nil {
		log.Fatal(err)
	}

	c.lastCertificate = certificates

	persistFiles(certificates)
	log.Printf("%#v\n", certificates)
}

func (c *certsClient) RenewCertificate() {
	log.Println("renewing currently existing certificate")
	certificates, err := c.legoClient.Certificate.Renew(*c.lastCertificate, true, false, "")
	if err != nil {
		log.Fatal(err)
	}

	c.lastCertificate = certificates

	persistFiles(certificates)
	log.Printf("%#v\n", certificates)
}

func persistFiles(certificates *certificate.Resource) {
	os.WriteFile("/certs/server.pem", certificates.Certificate, 0o644)
	os.WriteFile("/certs/server.key", certificates.PrivateKey, 0o644)
	jsonBytes, err := json.MarshalIndent(certificates, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	os.WriteFile("/certs/output.json", jsonBytes, 0o644)
}

func NewCertsClient(xip *xip.Xip, user *Account) *certsClient {
	config := lego.NewConfig(user)
	config.CADirURL = caDirUrl
	legoClient, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	provider := newProviderLocalIp(xip)
	legoClient.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}), dns01.DisableCompletePropagationRequirement())

	lastCertificate := getLastCertificate(legoClient)

	return &certsClient{
		legoClient,
		lastCertificate,
	}
}

func getLastCertificate(legoClient *lego.Client) *certificate.Resource {
	jsonBytes, err := os.ReadFile("/certs/output.json")
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil
		}
		log.Println(err)
		log.Println("falling back to getting a brand new cert")
		return nil
	}

	var lastCertificate = &certificate.Resource{}
	err = json.Unmarshal(jsonBytes, lastCertificate)
	if err != nil {
		log.Println(err)
		log.Println("falling back to getting a brand new cert")
		return nil
	}

	lastCertificate, err = legoClient.Certificate.Get(lastCertificate.CertURL, true)
	if err != nil {
		log.Println(err)
		log.Println("falling back to getting a brand new cert")
		return nil
	}

	return lastCertificate
}
