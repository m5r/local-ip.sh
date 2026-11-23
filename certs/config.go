// Package certs obtains, stores and renews the two certificates of the service, one for the domain and one for its wildcard, from an ACME certificate authority with DNS-01 challenges this program publishes itself.
package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"local-ip.sh/internal/names"
)

const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ChallengeRecords publishes DNS-01 challenge values in the zone. *xip.Xip implements it.
type ChallengeRecords interface {
	AddChallenge(name, value string) error
	RemoveChallenge(name, value string) error
}

type Config struct {
	// DirectoryURL is the ACME directory of the certificate authority.
	DirectoryURL string
	// Email is the contact of the ACME account; it may be empty.
	Email string
	// Domain is the zone apex: one certificate is kept for Domain and one for *.Domain.
	Domain string
	// StateDir is where the account and the certificates are stored.
	StateDir string
	// Profile is the ACME profile to ask for; empty leaves the choice to the authority.
	Profile string
	// TrustedRoots verifies the authority's API endpoint; nil means the system roots.
	TrustedRoots *x509.CertPool
	// ValidationDelay is how long a challenge value stays published before the authority is asked to validate it; zero means DefaultValidationDelay.
	ValidationDelay time.Duration
	Records         ChallengeRecords
	Logger          zerolog.Logger
}

// DefaultValidationDelay is the 60 seconds Let's Encrypt's validation resolvers may keep an answer, plus a margin. Both certificates are validated at one record name with different values, and a resolver that still holds what the name answered earlier fails the order. Once a value has been published for longer than any cache lives, whatever a resolver holds contains it.
const DefaultValidationDelay = 75 * time.Second

// Certificate is one issued certificate with its key. A published value is never modified.
type Certificate struct {
	// TLS is ready for crypto/tls, with Leaf set.
	TLS tls.Certificate
	// ChainPEM is the chain as the authority delivered it, leaf first.
	ChainPEM []byte
	// KeyPEM is the private key, one PEM block in its canonical encoding.
	KeyPEM []byte
}

// checkConfig returns an error for a configuration that can never work, an email that is not a bare address among them, and otherwise cfg with Domain in canonical form and a zero ValidationDelay replaced by DefaultValidationDelay. Applying it to its own result changes nothing. newStore and newACMEAuthority expect a configuration that went through it.
func checkConfig(cfg Config) (Config, error) {
	domain, err := names.Canonical(cfg.Domain)
	if err != nil {
		return Config{}, fmt.Errorf("certs: %w", err)
	}
	cfg.Domain = domain
	if cfg.Email != "" {
		if address, err := mail.ParseAddress(cfg.Email); err != nil || address.Address != cfg.Email {
			return Config{}, fmt.Errorf("certs: email %q is not a bare address", cfg.Email)
		}
	}
	if _, err := authorityDirName(cfg.DirectoryURL); err != nil {
		return Config{}, fmt.Errorf("certs: %w", err)
	}
	if cfg.StateDir == "" {
		return Config{}, errors.New("certs: no state directory")
	}
	if cfg.Records == nil {
		return Config{}, errors.New("certs: no challenge records")
	}
	if cfg.ValidationDelay < 0 {
		return Config{}, fmt.Errorf("certs: validation delay %v is negative", cfg.ValidationDelay)
	}
	if cfg.ValidationDelay == 0 {
		cfg.ValidationDelay = DefaultValidationDelay
	}
	return cfg, nil
}

// authorityDirName is the directory of the state that belongs to the authority at directoryURL: its host, with the port if any, followed by its path, lower-cased, every byte outside [a-z0-9.-] replaced by "_". It fails for anything but an absolute https URL.
func authorityDirName(directoryURL string) (string, error) {
	u, err := url.Parse(directoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("directory URL %q is not an absolute https URL", directoryURL)
	}
	name := []byte(u.Host + u.Path)
	for i, b := range name {
		switch {
		case b >= 'A' && b <= 'Z':
			name[i] = b + 'a' - 'A'
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '.', b == '-':
		default:
			name[i] = '_'
		}
	}
	// A host made of dots alone would name the state directory itself or its parent.
	if string(name) == "." || string(name) == ".." {
		return "", fmt.Errorf("directory URL %q is not an absolute https URL", directoryURL)
	}
	return string(name), nil
}
