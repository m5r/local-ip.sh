package certs

import (
	"fmt"
	"net/url"

	"github.com/go-acme/lego/v4/lego"
)

const (
	email    = "admin@local-ip.sh"
	caDirUrl = lego.LEDirectoryProduction
	// caDirUrl = lego.LEDirectoryStaging
)

var (
	parsedCaDirUrl, _ = url.Parse(caDirUrl)
	caDirHostname     = parsedCaDirUrl.Hostname()
	accountFilePath   = fmt.Sprintf("./.lego/accounts/%s/%s/account.json", caDirHostname, email)
	keyFilePath       = fmt.Sprintf("./.lego/accounts/%s/%s/keys/%s.key", caDirHostname, email, email)
)
