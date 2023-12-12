package xip

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Xip struct {
	server      dns.Server
	zone        string
	nameServers []*dns.NS
}

type HardcodedRecord struct {
	A     []*dns.A
	AAAA  []*dns.AAAA
	TXT   *dns.TXT
	MX    []*dns.MX
	CNAME []*dns.CNAME
}

var (
	flyRegion        = os.Getenv("FLY_REGION")
	dottedIpV4Regex  = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex  = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
	hardcodedRecords = map[string]HardcodedRecord{
		"ns.local-ip.sh.": {
			// record holding ip addresses of ns1 and ns2
			A: []*dns.A{
				{A: net.IPv4(137, 66, 25, 53)},
				{A: net.IPv4(188, 93, 146, 54)},
			},
		},
		"ns1.local-ip.sh.": {
			A: []*dns.A{
				{A: net.IPv4(137, 66, 25, 53)}, // fly.io global ip address
			},
		},
		"ns2.local-ip.sh.": {
			A: []*dns.A{
				{A: net.IPv4(188, 93, 146, 54)}, // fly.io global ip address #2
			},
		},
		"local-ip.sh.": {
			A: []*dns.A{
				{A: net.IPv4(213, 188, 218, 137)},
			},
			AAAA: []*dns.AAAA{
				{AAAA: net.IP{0x2a, 0x09, 0x82, 0x80, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x91, 0x65}},
			},
			TXT: &dns.TXT{
				Txt: []string{
					"sl-verification=frudknyqpqlpgzbglkqnsmorfcvxrf",
					"v=spf1 include:simplelogin.co ~all",
				},
			},
			MX: []*dns.MX{
				{Preference: 10, Mx: "mx1.simplelogin.co."},
				{Preference: 20, Mx: "mx2.simplelogin.co."},
			},
		},
		"_dmarc.local-ip.sh.": {
			TXT: &dns.TXT{
				Txt: []string{"v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s"},
			},
		},
		"dkim._domainkey.local-ip.sh.": {
			CNAME: []*dns.CNAME{
				{Target: "dkim._domainkey.simplelogin.co."},
			},
		},
		"dkim02._domainkey.local-ip.sh.": {
			CNAME: []*dns.CNAME{
				{Target: "dkim02._domainkey.simplelogin.co."},
			},
		},
		"dkim03._domainkey.local-ip.sh.": {
			CNAME: []*dns.CNAME{
				{Target: "dkim03._domainkey.simplelogin.co."},
			},
		},
		"_acme-challenge.local-ip.sh.": {
			// if fly
			/* CNAME: []*dns.CNAME{
				{Target: "local-ip.sh.n2kl11.flydns.net."},
			}, */
			// if manual
			TXT: &dns.TXT{},
		},
	}
)

func (xip *Xip) SetTXTRecord(fqdn string, value string) {
	log.Printf("trying to set TXT record \"%s\" for fqdn \"%s\"", value, fqdn)
	if fqdn != "_acme-challenge.local-ip.sh." {
		log.Println("not allowed, abort")
		return
	}

	if records, ok := hardcodedRecords[fqdn]; ok {
		records.TXT = &dns.TXT{
			Txt: []string{value},
		}
		hardcodedRecords["_acme-challenge.local-ip.sh."] = records
	}
}

func (xip *Xip) UnsetTXTRecord(fqdn string) {
	log.Printf("trying to unset TXT record for fqdn \"%s\"", fqdn)
	if fqdn != "_acme-challenge.local-ip.sh." {
		log.Println("not allowed, abort")
		return
	}

	if records, ok := hardcodedRecords[fqdn]; ok {
		records.TXT = nil
		hardcodedRecords["_acme-challenge.local-ip.sh."] = records
	}
}

func (xip *Xip) fqdnToA(fqdn string) []*dns.A {
	if hardcodedRecords[strings.ToLower(fqdn)].A != nil {
		var records []*dns.A

		for _, record := range hardcodedRecords[strings.ToLower(fqdn)].A {
			records = append(records, &dns.A{
				Hdr: dns.RR_Header{
					// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
					Ttl:    uint32((time.Second * 10).Seconds()),
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: record.A,
			})
		}

		return records
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
					// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
					Ttl:    uint32((time.Second * 10).Seconds()),
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
	records := xip.fqdnToA(fqdn)

	if len(records) == 0 {
		message.Rcode = dns.RcodeNameError
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range records {
		log.Printf("(%s) %s => %s\n", flyRegion, fqdn, record.A)
		message.Answer = append(message.Answer, record)
	}
}

func (xip *Xip) handleAAAA(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	if hardcodedRecords[strings.ToLower(fqdn)].AAAA == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[strings.ToLower(fqdn)].AAAA {
		message.Answer = append(message.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
				Ttl:    uint32((time.Second * 10).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
			},
			AAAA: record.AAAA,
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
				// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
				Ttl:    uint32((time.Second * 10).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: ns.Ns,
		})

		additionals = append(additionals, xip.fqdnToA(ns.Ns)...)
	}

	for _, record := range nameServers {
		message.Answer = append(message.Answer, record)
	}

	for _, record := range additionals {
		message.Extra = append(message.Extra, record)
	}
}

func (xip *Xip) handleTXT(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	if hardcodedRecords[strings.ToLower(fqdn)].TXT == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	message.Answer = append(message.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
			Ttl:    uint32((time.Second * 120).Seconds()),
			Name:   fqdn,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: hardcodedRecords[strings.ToLower(fqdn)].TXT.Txt,
	})
}

func (xip *Xip) handleMX(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	if hardcodedRecords[strings.ToLower(fqdn)].MX == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[strings.ToLower(fqdn)].MX {
		message.Answer = append(message.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
				Ttl:    uint32((time.Second * 10).Seconds()),
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
	if hardcodedRecords[strings.ToLower(fqdn)].CNAME == nil {
		xip.answerWithAuthority(question, message)
		return
	}

	for _, record := range hardcodedRecords[strings.ToLower(fqdn)].CNAME {
		message.Answer = append(message.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
				Ttl:    uint32((time.Second * 10).Seconds()),
				Name:   fqdn,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
			},
			Target: record.Target,
		})
	}
}

func (xip *Xip) handleSOA(question dns.Question, message *dns.Msg) {
	message.Answer = append(message.Answer, xip.soaRecord(question))
}

func (xip *Xip) soaRecord(question dns.Question) *dns.SOA {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:   question.Name,
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		// Ttl:      uint32((time.Hour * 24 * 7).Seconds()),
		Ttl:      uint32((time.Second * 10).Seconds()),
		Rdlength: 0,
	}
	soa.Ns = "ns1.local-ip.sh."
	soa.Mbox = "admin.local-ip.sh."
	soa.Serial = 2022102800
	// soa.Refresh = uint32((time.Minute * 15).Seconds())
	soa.Refresh = uint32((time.Second * 10).Seconds())
	// soa.Retry = uint32((time.Minute * 15).Seconds())
	soa.Retry = uint32((time.Second * 10).Seconds())
	// soa.Expire = uint32((time.Minute * 30).Seconds())
	soa.Expire = uint32((time.Second * 10).Seconds())
	// soa.Minttl = uint32((time.Minute * 5).Seconds())
	soa.Minttl = uint32((time.Second * 10).Seconds())

	return soa
}

func (xip *Xip) handleQuery(message *dns.Msg) {
	for _, question := range message.Question {
		// log.Printf("name: %s\n", question.Name)
		// log.Printf("class: %d\n", question.Qclass)
		// log.Printf("type: %d\n", question.Qtype)

		/* if strings.HasPrefix(strings.ToLower(question.Name), "_acme-challenge.") {
			message.Authoritative = false
		} */

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

		response.WriteMsg(message)
	}()
}

func (xip *Xip) StartServer() {
	log.Printf("Listening on %s\n", xip.server.Addr)
	err := xip.server.ListenAndServe()
	defer xip.server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func NewXip(zone string, nameservers []string, port int) (xip *Xip) {
	xip = &Xip{}

	for _, ns := range nameservers {
		xip.nameServers = append(xip.nameServers, &dns.NS{Ns: ns})
	}

	xip.server = dns.Server{
		Addr: fmt.Sprintf("fly-global-services:%d", port),
		Net:  "udp",
	}

	dns.HandleFunc(zone, xip.handleDnsRequest)

	return xip
}
