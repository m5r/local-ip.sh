package certs

import (
	"fmt"
	"net/url"

	"github.com/go-acme/lego/v4/lego"
)

const (
	email    = "admin@local-ip.sh"
	caDirUrl = lego.LEDirectoryProduction
)

var parsedCaDirUrl, _ = url.Parse(caDirUrl)
var caDirHostname = parsedCaDirUrl.Hostname()
var accountFilePath = fmt.Sprintf("./.lego/accounts/%s/%s/account.json", caDirHostname, email)
var keyFilePath = fmt.Sprintf("./.lego/accounts/%s/%s/keys/%s.key", caDirHostname, email, email)
