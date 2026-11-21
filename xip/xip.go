package xip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"local-ip.sh/internal/names"
	"local-ip.sh/utils"
)

// shutdownTimeout bounds how long Serve waits for the handlers in flight once its context is cancelled.
const shutdownTimeout = 2 * time.Second

type Xip struct {
	nameServerAddresses []string
	domain              string
	email               string
	zoneFile            string
	zone                *zone
	logger              zerolog.Logger
	challengeName       string
	challengeMu         sync.RWMutex
	challengeValues     map[string]struct{}
}

type Option func(*Xip)

func WithDomain(domain string) Option {
	return func(x *Xip) {
		x.domain = domain
	}
}

func WithEmail(email string) Option {
	return func(x *Xip) {
		x.email = email
	}
}

func WithZoneFile(path string) Option {
	return func(x *Xip) {
		x.zoneFile = path
	}
}

func WithLogger(logger zerolog.Logger) Option {
	return func(x *Xip) {
		x.logger = logger
	}
}

// WithNameServers sets the IPv4 addresses of the zone's name servers, served as ns1, ns2 and so on in the order given, and as the A records of the apex.
func WithNameServers(addresses []string) Option {
	return func(x *Xip) {
		x.nameServerAddresses = slices.Clone(addresses)
	}
}

var flyRegion = os.Getenv("FLY_REGION")

func chunkBy(str string, chunkSize int) (chunks []string) {
	for chunkSize < len(str) {
		str, chunks = str[chunkSize:], append(chunks, str[0:chunkSize])
	}
	return append(chunks, str)
}

func emailToRname(email string) string {
	parts := strings.SplitN(email, "@", 2)
	localPart := strings.ReplaceAll(parts[0], ".", "\\.")
	domain := parts[1]
	return localPart + "." + domain + "."
}

func (xip *Xip) handleDnsRequest(response dns.ResponseWriter, request *dns.Msg) {
	message := new(dns.Msg)
	message.SetReply(request)
	message.Compress = true
	message.RecursionAvailable = false
	// The server validates nothing, so the CD flag SetReply copied from the query would be a false claim (RFC 8906 section 8.1.3.1).
	message.CheckingDisabled = false
	xip.answer(request, message)

	if err := response.WriteMsg(message); err != nil {
		event := xip.logger.Error().Err(err)
		if len(message.Question) > 0 {
			question := message.Question[0]
			event.Str("name", question.Name).Str("type", dns.Type(question.Qtype).String())
		}
		event.Msg("Error responding to query")
		return
	}

	xip.logResolved(message)
}

// answer fills message, the reply SetReply built for request, by the first rule of B3 that matches.
// The refusals look at the request: SetReply keeps only its first question.
func (xip *Xip) answer(request, message *dns.Msg) {
	if request.Opcode != dns.OpcodeQuery {
		message.Rcode = dns.RcodeNotImplemented
		return
	}
	if len(request.Question) != 1 {
		message.Rcode = dns.RcodeFormatError
		return
	}
	question := request.Question[0]
	switch {
	case question.Qclass == 0:
		// The library parses a question cut short after its name or its type with class 0, a value no query may carry (RFC 6895 section 3.2).
		message.Rcode = dns.RcodeFormatError
		return
	case question.Qclass != dns.ClassINET, question.Qtype == dns.TypeAXFR, question.Qtype == dns.TypeIXFR:
		message.Rcode = dns.RcodeRefused
		return
	case !dns.IsSubDomain(xip.zone.apex, question.Name):
		message.Rcode = dns.RcodeRefused
		return
	}

	name := dns.CanonicalName(question.Name)
	if cut, d, ok := xip.zone.cuts.find(name); ok {
		// A DS record set at a cut belongs to the parent zone (RFC 4035 section 3.1.4.1), which is this one and has none.
		if question.Qtype != dns.TypeDS || name != cut {
			message.Ns = copies(d.nameServers)
			message.Extra = copies(d.glue)
			return
		}
		message.Authoritative = true
		message.Ns = xip.zone.negativeAuthority(xip.zone.negativeTTL())
		return
	}

	message.Authoritative = true
	if name == xip.challengeName {
		xip.handleChallenge(question, message)
		return
	}

	kind, answer, additional := xip.zone.lookup(question, name)
	switch kind {
	case lookupAnswer:
		message.Answer = answer
		message.Extra = additional
	case lookupNoData:
		message.Ns = xip.zone.negativeAuthority(xip.zone.negativeTTL())
	case lookupNoName:
		message.Rcode = dns.RcodeNameError
		message.Ns = xip.zone.negativeAuthority(xip.zone.negativeTTL())
	}
}

// logResolved computes nothing unless debug is enabled: at the default level this runs once per
// query and must cost no more than the level check.
func (xip *Xip) logResolved(message *dns.Msg) {
	event := xip.logger.Debug()
	if !event.Enabled() {
		return
	}

	if len(message.Question) > 0 {
		question := message.Question[0]
		event.Str("name", question.Name).Str("type", dns.Type(question.Qtype).String())
	}

	rcode, ok := dns.RcodeToString[message.Rcode]
	if !ok {
		rcode = fmt.Sprintf("RCODE%d", message.Rcode)
	}
	event.Str("rcode", rcode)

	answers := make([]string, 0, len(message.Answer))
	for _, answer := range message.Answer {
		answers = append(answers, strings.Join(strings.Fields(answer.String()), " "))
	}
	event.Strs("answers", answers)

	if flyRegion != "" {
		event.Str("FLY_REGION", flyRegion)
	}
	event.Msg("resolved")
}

// Serve answers the queries arriving on conn until ctx is cancelled, then stops reading, waits for the handlers in flight and returns nil.
// It returns the error of the read loop if that stops by itself. It takes ownership of conn and closes it in every case.
func (xip *Xip) Serve(ctx context.Context, conn net.PacketConn) error {
	if conn == nil {
		return errors.New("xip: serve: no socket")
	}
	// The server closes conn on most paths but not when ActivateAndServe fails before reading, and a second Close is harmless.
	defer conn.Close()

	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		Handler:           dns.HandlerFunc(xip.handleDnsRequest),
		NotifyStartedFunc: func() { close(started) },
	}
	served := make(chan error, 1)
	go func() { served <- server.ActivateAndServe() }()

	// Shutdown refuses a server that has not started, so the context is only watched once the read loop runs.
	select {
	case <-started:
	case err := <-served:
		return fmt.Errorf("xip: serving DNS on %s: %w", conn.LocalAddr(), err)
	}
	xip.logger.Info().Str("dns_address", conn.LocalAddr().String()).Msg("Starting up DNS server")

	select {
	case err := <-served:
		if err == nil {
			return errors.New("xip: DNS read loop stopped without being shut down")
		}
		return fmt.Errorf("xip: serving DNS on %s: %w", conn.LocalAddr(), err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := server.ShutdownContext(shutdownCtx); err != nil {
		xip.logger.Warn().Err(err).Msg("DNS server did not shut down cleanly")
	}
	// ShutdownContext has closed the socket by now, on time or at its limit, which ends any handler blocked on its reply, so a handler can only still be busy writing a log line; waiting keeps the promise that no handler runs after Serve returns, and the wait is not bounded because it only happens during a shutdown, which the supervisor's kill timeout or a second signal ends if it hangs.
	if err := <-served; err != nil {
		return fmt.Errorf("xip: serving DNS on %s: %w", conn.LocalAddr(), err)
	}
	return nil
}

// NewXip builds a server for one zone. It requires a valid domain (WithDomain), a bare email address for the SOA record (WithEmail) and at least one IPv4 name server address (WithNameServers). It reads no process-wide configuration and binds no socket: see Serve.
func NewXip(opts ...Option) (*Xip, error) {
	xip := &Xip{
		logger:          utils.Logger,
		challengeValues: make(map[string]struct{}),
	}

	for _, opt := range opts {
		opt(xip)
	}

	domain, err := names.Canonical(xip.domain)
	if err != nil {
		return nil, fmt.Errorf("xip: %w", err)
	}
	xip.domain = domain
	xip.challengeName = challengeLabel + domain + "."

	if address, err := mail.ParseAddress(xip.email); err != nil || address.Address != xip.email {
		return nil, fmt.Errorf("xip: email %q is not a bare address", xip.email)
	}

	if len(xip.nameServerAddresses) == 0 {
		return nil, errors.New("xip: at least one name server is required")
	}
	addresses := make([]netip.Addr, len(xip.nameServerAddresses))
	for i, ns := range xip.nameServerAddresses {
		addr, err := netip.ParseAddr(ns)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("xip: name server %q is not an IPv4 address", ns)
		}
		addresses[i] = addr
	}

	var file *zoneFile
	if xip.zoneFile != "" {
		f, err := os.Open(xip.zoneFile)
		if err != nil {
			return nil, fmt.Errorf("opening zone file %s: %w", xip.zoneFile, err)
		}
		defer f.Close()
		file, err = parseZoneFile(f, xip.zoneFile, zoneServer{
			origin:        domain,
			nameServers:   nameServerNames(domain+".", len(addresses)),
			challengeName: xip.challengeName,
			addresses:     addresses,
		})
		if err != nil {
			return nil, err
		}
	}

	zone, err := newZone(domain, xip.email, addresses, file)
	if err != nil {
		return nil, err
	}
	xip.zone = zone

	if file != nil {
		cuts := file.cuts.sortedCuts()
		xip.logger.Info().
			Str("zone_file", xip.zoneFile).
			Int("delegations", len(cuts)).
			Strs("cuts", cuts).
			Int("records", len(file.records)).
			Msg("Loaded zone file")
	}
	return xip, nil
}
