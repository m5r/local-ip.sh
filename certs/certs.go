package certs

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"local-ip.sh/utils"
	"local-ip.sh/xip"
)

type certsClient struct {
	legoClient              *lego.Client
	lastWildcardCertificate *certificate.Resource
	lastRootCertificate     *certificate.Resource
}

func (c *certsClient) RequestCertificates() {
	c.requestCertificate("wildcard")
	c.requestCertificate("root")
}

func (c *certsClient) requestCertificate(certType string) {
	var lastCertificate *certificate.Resource
	var domains []string
	if certType == "wildcard" {
		lastCertificate = c.lastWildcardCertificate
		domains = []string{"*.local-ip.sh"}
	} else if certType == "root" {
		lastCertificate = c.lastRootCertificate
		domains = []string{"local-ip.sh"}
	} else {
		utils.Logger.Fatal().Msgf("Unexpected certType %s. Only \"wildcard\" and \"root\" are supported", certType)
	}

	utils.Logger.Info().Str("certType", certType).Msg("Requesting certificate")
	if lastCertificate != nil {
		certificates, err := certcrypto.ParsePEMBundle(c.lastWildcardCertificate.Certificate)
		if err != nil {
			utils.Logger.Fatal().Err(err).Msg("Failed to parse PEM bundle from last certificate")
		}

		x509Cert := certificates[0]
		timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
		if timeLeft > time.Hour*24*30 {
			utils.Logger.Info().Msgf("%d days left before expiration, skip renewal", int(timeLeft.Hours()/24))
			return
		}

		c.renewCertificates()
		return
	}

	cert, err := c.legoClient.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to obtain certificate from lego client")
	}

	if certType == "wildcard" {
		c.lastWildcardCertificate = cert
	} else if certType == "root" {
		c.lastRootCertificate = cert
	}

	persistFiles(cert, certType)

}

func (c *certsClient) renewCertificates() {
	utils.Logger.Info().Msg("Renewing certificates")

	wildcardCertificate, err := c.legoClient.Certificate.Renew(*c.lastWildcardCertificate, true, false, "")
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to renew wildcard certificate")
	}
	c.lastWildcardCertificate = wildcardCertificate
	persistFiles(wildcardCertificate, "wildcard")

	rootCertificate, err := c.legoClient.Certificate.Renew(*c.lastRootCertificate, true, false, "")
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to renew root certificate")
	}
	c.lastRootCertificate = rootCertificate
	persistFiles(rootCertificate, "root")

}

func persistFiles(certificates *certificate.Resource, certType string) {
	err := os.MkdirAll(fmt.Sprintf("./.lego/certs/%s", certType), 0o755)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msgf("Failed to mkdir ./.lego/certs/%s", certType)
	}

	err = os.WriteFile(fmt.Sprintf("./.lego/certs/%s/server.pem", certType), certificates.Certificate, 0o644)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msgf("Failed to save ./.lego/certs/%s/server.pem", certType)
	}

	os.WriteFile(fmt.Sprintf("./.lego/certs/%s/server.key", certType), certificates.PrivateKey, 0o644)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msgf("Failed to save ./.lego/certs/%s/server.key", certType)
	}

	jsonBytes, err := json.MarshalIndent(certificates, "", "\t")
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to marshal certificates to JSON")
	}

	err = os.WriteFile(fmt.Sprintf("./.lego/certs/%s/output.json", certType), jsonBytes, 0o644)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msgf("Failed to save ./.lego/certs/%s/output.json", certType)
	}
}

func NewCertsClient(xip *xip.Xip, user *Account) *certsClient {
	config := lego.NewConfig(user)
	config.CADirURL = caDirUrl
	legoClient, err := lego.NewClient(config)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to initialize lego client")
	}

	provider := newProviderLocalIp(xip)
	legoClient.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}), dns01.DisableCompletePropagationRequirement())

	lastWildcardCertificate := getLastCertificate(legoClient, "wildcard")
	lastRootCertificate := getLastCertificate(legoClient, "root")

	return &certsClient{
		legoClient,
		lastWildcardCertificate,
		lastRootCertificate,
	}
}

func getLastCertificate(legoClient *lego.Client, certType string) *certificate.Resource {
	jsonBytes, err := os.ReadFile(fmt.Sprintf("./.lego/certs/%s/output.json", certType))
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil
		}
		utils.Logger.Error().Err(err).Msg("Failling back to getting a brand new cert")
		return nil
	}

	lastCertificate := &certificate.Resource{}
	err = json.Unmarshal(jsonBytes, lastCertificate)
	if err != nil {
		utils.Logger.Error().Err(err).Msg("Failling back to getting a brand new cert")
		return nil
	}

	lastCertificate, err = legoClient.Certificate.Get(lastCertificate.CertURL, true)
	if err != nil {
		utils.Logger.Error().Err(err).Msg("Failling back to getting a brand new cert")
		return nil
	}

	return lastCertificate
}
