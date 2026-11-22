package xip

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"local-ip.sh/internal/names"
	"local-ip.sh/utils"
)

type Xip struct {
	nameServerAddresses []string
	domain              string
	email               string
	zoneFile            string
	zone                *zone
	logger              zerolog.Logger
	region              string
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

// WithRegion names the region the server runs in, which every resolved query's log line carries; empty leaves the field out.
func WithRegion(region string) Option {
	return func(x *Xip) {
		x.region = region
	}
}

// WithNameServers sets the IPv4 addresses of the zone's name servers, served as ns1, ns2 and so on in the order given, and as the A records of the apex.
func WithNameServers(addresses []string) Option {
	return func(x *Xip) {
		x.nameServerAddresses = slices.Clone(addresses)
	}
}

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
	message.RecursionAvailable = false
	// The server validates nothing, so the CD flag SetReply copied from the query would be a false claim (RFC 8906 section 8.1.3.1).
	message.CheckingDisabled = false

	// A query whose EDNS the server does not understand gets the EDNS error alone, before any other rule looks at it (RFC 6891 sections 6.1.1 and 6.1.3).
	queryOPT, optCount := ednsOf(request)
	switch {
	case optCount > 1:
		message.Rcode = dns.RcodeFormatError
	case queryOPT != nil && queryOPT.Version() != 0:
		message.Rcode = dns.RcodeBadVers
	default:
		xip.answer(request, message)
	}
	if queryOPT != nil {
		message.Extra = append(message.Extra, replyOPT(queryOPT.Do()))
	}
	message.Truncate(replyLimit(response.LocalAddr(), queryOPT))

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
	switch {
	case message.Rcode == dns.RcodeBadVers:
		// The library's table names 16 after its meaning in a TSIG record, BADSIG, but in a reply's header and OPT record it is BADVERS.
		rcode = "BADVERS"
	case !ok:
		rcode = fmt.Sprintf("RCODE%d", message.Rcode)
	}
	event.Str("rcode", rcode)

	answers := make([]string, 0, len(message.Answer))
	for _, answer := range message.Answer {
		answers = append(answers, strings.Join(strings.Fields(answer.String()), " "))
	}
	event.Strs("answers", answers)

	if xip.region != "" {
		event.Str("FLY_REGION", xip.region)
	}
	event.Msg("resolved")
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
