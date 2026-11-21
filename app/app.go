// Package app assembles the DNS server, the certificate manager and the web server into one program, and owns their sockets and their lifetimes.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"local-ip.sh/certs"
	web "local-ip.sh/http"
	"local-ip.sh/internal/names"
	"local-ip.sh/xip"
)

// Config is everything the program needs; nothing is read from the environment or from process-wide state.
type Config struct {
	// Domain is the zone apex, Email the administrator's address (SOA record and ACME account), NameServers the IPv4 addresses of ns1, ns2, ... .Domain.
	Domain      string
	Email       string
	NameServers []string
	// ZoneFile is the path of the delegations file; empty means none.
	ZoneFile string

	// DNSUDPAddress and DNSTCPAddress are where the DNS server listens over each transport, HTTPAddress and HTTPSAddress where the web server listens; all are listen addresses in the form net.Listen takes. The DNS addresses are separate because a host may deliver UDP and TCP to different interfaces, as Fly does.
	DNSUDPAddress string
	DNSTCPAddress string
	HTTPAddress   string
	HTTPSAddress  string

	// StateDir holds the ACME account and the certificates, StaticDir the website's files.
	StateDir  string
	StaticDir string

	// DirectoryURL, ACMEProfile, TrustedRoots and ValidationDelay go to certs.Config unchanged.
	DirectoryURL    string
	ACMEProfile     string
	TrustedRoots    *x509.CertPool
	ValidationDelay time.Duration

	Logger zerolog.Logger
}

// App is the assembled program with its sockets bound.
type App struct {
	dns          *xip.Xip
	certificates *certs.Manager
	web          *web.Server

	dnsConn       net.PacketConn
	dnsListener   net.Listener
	httpListener  net.Listener
	httpsListener net.Listener

	ran atomic.Bool
}

// New builds the DNS server, the certificate manager and the web server, which loads the zone file and the stored certificates, then binds the four sockets. Nothing is served yet. When it returns an error nothing stays bound.
func New(cfg Config) (*App, error) {
	domain, err := names.Canonical(cfg.Domain)
	if err != nil {
		return nil, err
	}

	dnsOptions := []xip.Option{
		xip.WithDomain(domain),
		xip.WithEmail(cfg.Email),
		xip.WithNameServers(cfg.NameServers),
		xip.WithLogger(cfg.Logger),
	}
	if cfg.ZoneFile != "" {
		dnsOptions = append(dnsOptions, xip.WithZoneFile(cfg.ZoneFile))
	}
	dnsServer, err := xip.NewXip(dnsOptions...)
	if err != nil {
		return nil, fmt.Errorf("DNS server: %w", err)
	}

	manager, err := certs.NewManager(certs.Config{
		DirectoryURL:    cfg.DirectoryURL,
		Email:           cfg.Email,
		Domain:          domain,
		StateDir:        cfg.StateDir,
		Profile:         cfg.ACMEProfile,
		TrustedRoots:    cfg.TrustedRoots,
		ValidationDelay: cfg.ValidationDelay,
		Records:         dnsServer,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	webServer := web.NewServer(web.Options{
		Certificates: certificateSource{manager: manager},
		StaticDir:    cfg.StaticDir,
		Logger:       cfg.Logger,
	})

	a := &App{dns: dnsServer, certificates: manager, web: webServer}
	if err := a.bind(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *App) bind(cfg Config) (err error) {
	var bound []interface{ Close() error }
	defer func() {
		if err != nil {
			for _, socket := range bound {
				socket.Close()
			}
		}
	}()

	a.dnsConn, err = net.ListenPacket("udp", cfg.DNSUDPAddress)
	if err != nil {
		return fmt.Errorf("listening for DNS over UDP on %s: %w", cfg.DNSUDPAddress, err)
	}
	bound = append(bound, a.dnsConn)

	a.dnsListener, err = net.Listen("tcp", cfg.DNSTCPAddress)
	if err != nil {
		return fmt.Errorf("listening for DNS over TCP on %s: %w", cfg.DNSTCPAddress, err)
	}
	bound = append(bound, a.dnsListener)

	a.httpListener, err = net.Listen("tcp", cfg.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listening for HTTP on %s: %w", cfg.HTTPAddress, err)
	}
	bound = append(bound, a.httpListener)

	a.httpsListener, err = net.Listen("tcp", cfg.HTTPSAddress)
	if err != nil {
		return fmt.Errorf("listening for HTTPS on %s: %w", cfg.HTTPSAddress, err)
	}
	return nil
}

// DNSUDPAddr is the UDP address New bound for DNS.
func (a *App) DNSUDPAddr() net.Addr { return a.dnsConn.LocalAddr() }

// DNSTCPAddr is the TCP address New bound for DNS.
func (a *App) DNSTCPAddr() net.Addr { return a.dnsListener.Addr() }

// HTTPAddr is the TCP address New bound for plain HTTP.
func (a *App) HTTPAddr() net.Addr { return a.httpListener.Addr() }

// HTTPSAddr is the TCP address New bound for HTTPS.
func (a *App) HTTPSAddr() net.Addr { return a.httpsListener.Addr() }

// Run serves until ctx is cancelled, then stops the three components and returns nil. If one of them stops by itself, Run stops the others and returns an error that names it. Run owns the sockets New bound and must be called exactly once.
func (a *App) Run(ctx context.Context) error {
	if a.ran.Swap(true) {
		return errors.New("app: Run called more than once")
	}

	group, groupCtx := errgroup.WithContext(ctx)
	run := func(component string, serve func(context.Context) error) {
		group.Go(func() error {
			err := serve(groupCtx)
			switch {
			case err != nil:
				return fmt.Errorf("%s: %w", component, err)
			case groupCtx.Err() == nil:
				// A process whose DNS loop has ended must not stay up looking healthy, so a component that breaks its contract by returning nil on its own brings the others down like a failure would.
				return fmt.Errorf("%s stopped without being asked to", component)
			default:
				return nil
			}
		})
	}
	run("DNS server", func(ctx context.Context) error { return a.dns.Serve(ctx, a.dnsConn, a.dnsListener) })
	run("web server", func(ctx context.Context) error { return a.web.Run(ctx, a.httpListener, a.httpsListener) })
	run("certificate manager", a.certificates.Run)
	return group.Wait()
}

// RenewCertificates asks for both certificates to be renewed now. It never blocks.
func (a *App) RenewCertificates() {
	a.certificates.RenewNow()
}

// certificateSource lets the web server read the manager's certificates without either package importing the other.
type certificateSource struct {
	manager *certs.Manager
}

func (s certificateSource) SiteCertificate() *tls.Certificate {
	site := s.manager.Site()
	if site == nil {
		return nil
	}
	return &site.TLS
}

func (s certificateSource) PublishedPair() (web.Pair, bool) {
	wildcard := s.manager.Wildcard()
	if wildcard == nil {
		return web.Pair{}, false
	}
	return web.Pair{
		CertificatePEM: wildcard.ChainPEM,
		KeyPEM:         wildcard.KeyPEM,
		NotBefore:      wildcard.TLS.Leaf.NotBefore,
	}, true
}
