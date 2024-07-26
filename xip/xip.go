package xip

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"local-ip.sh/utils"
)

type Xip struct {
	server      dns.Server
	nameServers []string
}

var (
	flyRegion       = os.Getenv("FLY_REGION")
	dottedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
)

func (xip *Xip) SetTXTRecord(fqdn string, value string) {
	utils.Logger.Debug().Str("fqdn", fqdn).Str("value", value).Msg("Trying to set TXT record")
	config := utils.GetConfig()
	if fqdn != fmt.Sprintf("_acme-challenge.%s.", config.Domain) {
		utils.Logger.Debug().Msg("Not allowed, abort")
		return
	}

	if rootRecords, ok := hardcodedRecords[fqdn]; ok {
		rootRecords.TXT = []string{value}
		hardcodedRecords[fmt.Sprintf("_acme-challenge.%s.", config.Domain)] = rootRecords
	}
}

func (xip *Xip) UnsetTXTRecord(fqdn string) {
	utils.Logger.Debug().Str("fqdn", fqdn).Msg("Trying to set TXT record")
	config := utils.GetConfig()
	if fqdn != fmt.Sprintf("_acme-challenge.%s.", config.Domain) {
		utils.Logger.Debug().Msg("Not allowed, abort")
		return
	}

	if rootRecords, ok := hardcodedRecords[fqdn]; ok {
		rootRecords.TXT = []string{}
		hardcodedRecords[fmt.Sprintf("_acme-challenge.%s.", config.Domain)] = rootRecords
	}
}

func (xip *Xip) fqdnToA(fqdn string) []*dns.A {
	normalizedFqdn := strings.ToLower(fqdn)
	if hardcodedRecords[normalizedFqdn].A != nil {
		var aRecords []*dns.A

		for _, record := range hardcodedRecords[normalizedFqdn].A {
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
	message.Ns = append(message.Ns, xip.soaRecord(question))
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
	if hardcodedRecords[normalizedFqdn].AAAA == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[normalizedFqdn].AAAA {
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
	if hardcodedRecords[normalizedFqdn].TXT == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[normalizedFqdn].TXT {
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
	if hardcodedRecords[normalizedFqdn].MX == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[normalizedFqdn].MX {
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
	if hardcodedRecords[normalizedFqdn].CNAME == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[normalizedFqdn].CNAME {
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
	if hardcodedRecords[normalizedFqdn].SRV == nil {
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
		Priority: hardcodedRecords[normalizedFqdn].SRV.Priority,
		Weight:   hardcodedRecords[normalizedFqdn].SRV.Weight,
		Port:     hardcodedRecords[normalizedFqdn].SRV.Port,
		Target:   hardcodedRecords[normalizedFqdn].SRV.Target,
	})
}

func (xip *Xip) handleSOA(question dns.Question, message *dns.Msg) {
	message.Answer = append(message.Answer, xip.soaRecord(question))
}

func emailToRname(email string) string {
	parts := strings.SplitN(email, "@", 2)
	localPart := strings.ReplaceAll(parts[0], ".", "\\.")
	domain := parts[1]
	return localPart + "." + domain + "."
}

func (xip *Xip) soaRecord(question dns.Question) *dns.SOA {
	config := utils.GetConfig()
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:     question.Name,
		Rrtype:   dns.TypeSOA,
		Class:    dns.ClassINET,
		Ttl:      uint32((time.Minute * 5).Seconds()),
		Rdlength: 0,
	}
	soa.Ns = xip.nameServers[0]
	soa.Mbox = emailToRname(config.Email)
	soa.Serial = 2024072600
	soa.Refresh = uint32((time.Minute * 15).Seconds())
	soa.Retry = uint32((time.Minute * 15).Seconds())
	soa.Expire = uint32((time.Minute * 30).Seconds())
	soa.Minttl = uint32((time.Minute * 5).Seconds())

	return soa
}

func (xip *Xip) handleQuery(message *dns.Msg) {
	for _, question := range message.Question {
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
}

func (xip *Xip) handleDnsRequest(response dns.ResponseWriter, request *dns.Msg) {
	go func() {
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

		utils.Logger.Debug().Str("FLY_REGION", flyRegion).Any("question", request.Question).Any("answer", message.Answer).Msg("resolved")

		error := response.WriteMsg(message)
		if error != nil {
			utils.Logger.Debug().Msg(message.String())
			utils.Logger.Error().Err(error).Str("message", message.String()).Msg("Error responding to query")
		}
	}()
}

func (xip *Xip) StartServer() {
	if _, exists := os.LookupEnv("FLY_APP_NAME"); exists {
		// we're probably running on fly, bind to fly-global-services
		xip.server.Addr = "fly-global-services" + xip.server.Addr
	}

	err := xip.server.ListenAndServe()
	defer xip.server.Shutdown()
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to start DNS server")
		if strings.Contains(err.Error(), "fly-global-services: no such host") {
			// we're not running on fly, bind to 0.0.0.0 instead
			port := strings.Split(xip.server.Addr, ":")[1]
			xip.server = dns.Server{
				Addr: fmt.Sprintf(":%s", port),
				Net:  "udp",
			}

			xip.StartServer()
			return
		}

		utils.Logger.Fatal().Err(err).Msg("Failed to start DNS server")
	}
	utils.Logger.Info().Str("dns_address", xip.server.Addr).Msg("Starting up DNS server")
}

func (xip *Xip) initHardcodedRecords() {
	config := utils.GetConfig()
	rootDomainARecords := []net.IP{}

	for i, ns := range config.NameServers {
		name := fmt.Sprintf("ns%d.%s.", i+1, config.Domain)
		ip := net.ParseIP(ns)

		rootDomainARecords = append(rootDomainARecords, ip)
		entry := hardcodedRecords[name]
		entry.A = append(hardcodedRecords[name].A, ip)
		hardcodedRecords[name] = entry

		xip.nameServers = append(xip.nameServers, name)
	}

	hardcodedRecords[fmt.Sprintf("%s.", config.Domain)] = hardcodedRecord{A: rootDomainARecords}

	// will be filled in later when requesting certificates
	hardcodedRecords[fmt.Sprintf("_acme-challenge.%s.", config.Domain)] = hardcodedRecord{TXT: []string{}}
}

func NewXip() (xip *Xip) {
	config := utils.GetConfig()
	xip = &Xip{}

	xip.initHardcodedRecords()

	xip.server = dns.Server{
		Addr: fmt.Sprintf(":%d", config.DnsPort),
		Net:  "udp",
	}

	zone := fmt.Sprintf("%s.", config.Domain)
	dns.HandleFunc(zone, xip.handleDnsRequest)

	return xip
}
