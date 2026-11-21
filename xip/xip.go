package xip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
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
	nameServers         []string
	domain              string
	email               string
	recordsMu           sync.RWMutex
	records             map[string]hardcodedRecord
	zoneFile            string
	delegations         *zoneCuts
	logger              zerolog.Logger
	mux                 *dns.ServeMux
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

var (
	flyRegion       = os.Getenv("FLY_REGION")
	dottedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
)

func (xip *Xip) fqdnToA(fqdn string) []*dns.A {
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	records := xip.records[normalizedFqdn].A
	xip.recordsMu.RUnlock()
	if records != nil {
		var aRecords []*dns.A

		for _, record := range records {
			aRecords = append(aRecords, &dns.A{
				Hdr: dns.RR_Header{
					Ttl:    uint32((time.Minute * 5).Seconds()),
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: record,
			})
		}

		return aRecords
	}

	for _, ipV4RE := range []*regexp.Regexp{dashedIpV4Regex, dottedIpV4Regex} {
		if ipV4RE.MatchString(fqdn) {
			match := ipV4RE.FindStringSubmatch(fqdn)[1]
			match = strings.ReplaceAll(match, "-", ".")
			ipV4Address := net.ParseIP(match).To4()
			if ipV4Address == nil {
				return nil
			}

			return []*dns.A{{
				Hdr: dns.RR_Header{
					Ttl:    uint32((time.Minute * 5).Seconds()),
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: ipV4Address,
			}}
		}
	}

	return nil
}

func (xip *Xip) answerWithAuthority(question dns.Question, message *dns.Msg) {
	message.Ns = append(message.Ns, xip.soaRecord(question.Name, uint32((time.Minute*5).Seconds())))
}

func (xip *Xip) handleA(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	aRecords := xip.fqdnToA(fqdn)

	if len(aRecords) == 0 {
		message.Rcode = dns.RcodeNameError
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range aRecords {
		message.Answer = append(message.Answer, record)
	}
}

func (xip *Xip) handleAAAA(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	records := xip.records[normalizedFqdn].AAAA
	xip.recordsMu.RUnlock()
	if records == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range records {
		message.Answer = append(message.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Ttl:    uint32((time.Minute * 5).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
			},
			AAAA: record,
		})
	}
}

func (xip *Xip) handleNS(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	nameServers := []*dns.NS{}
	additionals := []*dns.A{}
	for _, ns := range xip.nameServers {
		nameServers = append(nameServers, &dns.NS{
			Hdr: dns.RR_Header{
				Ttl:    uint32((time.Minute * 5).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: ns,
		})

		additionals = append(additionals, xip.fqdnToA(ns)...)
	}

	for _, record := range nameServers {
		message.Answer = append(message.Answer, record)
	}

	for _, record := range additionals {
		message.Extra = append(message.Extra, record)
	}
}

func chunkBy(str string, chunkSize int) (chunks []string) {
	for chunkSize < len(str) {
		str, chunks = str[chunkSize:], append(chunks, str[0:chunkSize])
	}
	return append(chunks, str)
}

func (xip *Xip) handleTXT(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	records := xip.records[normalizedFqdn].TXT
	xip.recordsMu.RUnlock()
	if records == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range records {
		message.Answer = append(message.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Ttl:    uint32((time.Minute * 5).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: chunkBy(record, 255),
		})
	}
}

func (xip *Xip) handleMX(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	records := xip.records[normalizedFqdn].MX
	xip.recordsMu.RUnlock()
	if records == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range records {
		message.Answer = append(message.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Ttl:    uint32((time.Minute * 5).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
			},
			Mx:         record.Mx,
			Preference: record.Preference,
		})
	}
}

func (xip *Xip) handleCNAME(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	records := xip.records[normalizedFqdn].CNAME
	xip.recordsMu.RUnlock()
	if records == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range records {
		message.Answer = append(message.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Ttl:    uint32((time.Minute * 5).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
			},
			Target: record,
		})
	}
}

func (xip *Xip) handleSRV(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	normalizedFqdn := strings.ToLower(fqdn)
	xip.recordsMu.RLock()
	record := xip.records[normalizedFqdn].SRV
	xip.recordsMu.RUnlock()
	if record == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	message.Answer = append(message.Answer, &dns.SRV{
		Hdr: dns.RR_Header{
			Ttl:    uint32((time.Minute * 5).Seconds()),
			Name:   fqdn,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
		},
		Priority: record.Priority,
		Weight:   record.Weight,
		Port:     record.Port,
		Target:   record.Target,
	})
}

func (xip *Xip) handleSOA(question dns.Question, message *dns.Msg) {
	message.Answer = append(message.Answer, xip.soaRecord(question.Name, uint32((time.Minute*5).Seconds())))
}

func emailToRname(email string) string {
	parts := strings.SplitN(email, "@", 2)
	localPart := strings.ReplaceAll(parts[0], ".", "\\.")
	domain := parts[1]
	return localPart + "." + domain + "."
}

func (xip *Xip) soaRecord(name string, ttl uint32) *dns.SOA {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:     name,
		Rrtype:   dns.TypeSOA,
		Class:    dns.ClassINET,
		Ttl:      ttl,
		Rdlength: 0,
	}
	soa.Ns = xip.nameServers[0]
	soa.Mbox = emailToRname(xip.email)
	soa.Serial = 2024072600
	soa.Refresh = uint32((time.Minute * 15).Seconds())
	soa.Retry = uint32((time.Minute * 15).Seconds())
	soa.Expire = uint32((time.Minute * 30).Seconds())
	soa.Minttl = uint32((time.Minute * 5).Seconds())

	return soa
}

func (xip *Xip) handleQuery(message *dns.Msg) {
	if len(message.Question) != 1 {
		// see https://serverfault.com/a/742788
		xip.logger.Error().Any("questions", message.Question).Msg("Received an incorrect amount of questions")
		message.MsgHdr.Rcode = dns.RcodeFormatError
		return
	}

	question := message.Question[0]
	if cut, d, ok := xip.delegations.find(question.Name); ok {
		// A DS RRset at a zone cut belongs to the parent zone (RFC 4035 section 3.1.4.1).
		if question.Qtype != dns.TypeDS || dns.CanonicalName(question.Name) != cut {
			message.Authoritative = false
			message.Ns = append(message.Ns, d.nameServers...)
			message.Extra = append(message.Extra, d.glue...)
			return
		}
	}

	if dns.CanonicalName(question.Name) == xip.challengeName {
		xip.handleChallenge(question, message)
		return
	}

	switch question.Qtype {
	case dns.TypeA:
		xip.handleA(question, message)
	case dns.TypeAAAA:
		xip.handleAAAA(question, message)
	case dns.TypeNS:
		xip.handleNS(question, message)
	case dns.TypeTXT:
		xip.handleTXT(question, message)
	case dns.TypeMX:
		xip.handleMX(question, message)
	case dns.TypeCNAME:
		xip.handleCNAME(question, message)
	case dns.TypeSRV:
		xip.handleSRV(question, message)
	case dns.TypeSOA:
		xip.handleSOA(question, message)
	default:
		xip.handleSOA(question, message)
	}
}

func (xip *Xip) handleDnsRequest(response dns.ResponseWriter, request *dns.Msg) {
	message := new(dns.Msg)
	message.SetReply(request)
	message.Compress = true
	message.Authoritative = true
	message.RecursionAvailable = false

	switch request.Opcode {
	case dns.OpcodeQuery:
		xip.handleQuery(message)
	default:
		message.MsgHdr.Rcode = dns.RcodeRefused
	}

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
		Handler:           xip.mux,
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

func (xip *Xip) initNameServers() {
	rootDomainARecords := []net.IP{}

	xip.recordsMu.Lock()
	defer xip.recordsMu.Unlock()

	for i, ns := range xip.nameServerAddresses {
		name := fmt.Sprintf("ns%d.%s.", i+1, xip.domain)
		ip := net.ParseIP(ns)

		rootDomainARecords = append(rootDomainARecords, ip)
		entry := xip.records[name]
		entry.A = append(xip.records[name].A, ip)
		xip.records[name] = entry

		xip.nameServers = append(xip.nameServers, name)
	}

	xip.records[fmt.Sprintf("%s.", xip.domain)] = hardcodedRecord{A: rootDomainARecords}
}

func (xip *Xip) loadZoneFile() error {
	file, err := os.Open(xip.zoneFile)
	if err != nil {
		return fmt.Errorf("opening zone file %s: %w", xip.zoneFile, err)
	}
	defer file.Close()

	server := zoneServer{
		origin:   xip.domain,
		reserved: append(slices.Clone(xip.nameServers), xip.challengeName),
	}
	xip.recordsMu.RLock()
	for _, name := range xip.nameServers {
		for _, ip := range xip.records[name].A {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				server.addresses = append(server.addresses, addr.Unmap())
			}
		}
	}
	xip.recordsMu.RUnlock()

	delegations, err := parseDelegations(file, xip.zoneFile, server)
	if err != nil {
		return err
	}
	xip.delegations = delegations

	cuts := delegations.sortedCuts()
	xip.logger.Info().
		Str("zone_file", xip.zoneFile).
		Int("delegations", len(cuts)).
		Strs("cuts", cuts).
		Msg("Loaded zone file")
	return nil
}

// NewXip builds a server for one zone. It requires a valid domain (WithDomain), a bare email address for the SOA record (WithEmail) and at least one IPv4 name server address (WithNameServers). It reads no process-wide configuration and binds no socket: see Serve.
func NewXip(opts ...Option) (*Xip, error) {
	xip := &Xip{
		records:         initialRecords(),
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
	for _, ns := range xip.nameServerAddresses {
		if addr, err := netip.ParseAddr(ns); err != nil || !addr.Is4() {
			return nil, fmt.Errorf("xip: name server %q is not an IPv4 address", ns)
		}
	}
	xip.initNameServers()

	if xip.zoneFile != "" {
		if err := xip.loadZoneFile(); err != nil {
			return nil, err
		}
	}

	xip.mux = dns.NewServeMux()
	xip.mux.HandleFunc(domain+".", xip.handleDnsRequest)

	return xip, nil
}
