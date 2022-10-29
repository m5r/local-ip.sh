package xip

import (
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Xip struct {
	Server      dns.Server
	NameServers []*dns.NS
	Zone        string
}

var (
	flyRegion        = os.Getenv("FLY_REGION")
	dottedIpV4Regex  = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex  = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
	hardcodedDomains = map[string]net.IP{
		"ns.local-ip.sh.":  net.IPv4(137, 66, 38, 214),
		"ns1.local-ip.sh.": net.IPv4(137, 66, 38, 214),
		"ns2.local-ip.sh.": net.IPv4(137, 66, 38, 214),
	}
)

func (xip *Xip) fqdnToA(fqdn string) *dns.A {
	var ipV4Address net.IP

	if hardcodedDomains[strings.ToLower(fqdn)] != nil {
		ipV4Address = hardcodedDomains[strings.ToLower(fqdn)]
	} else {
		for _, ipV4RE := range []*regexp.Regexp{dashedIpV4Regex, dottedIpV4Regex} {
			if ipV4RE.MatchString(fqdn) {
				match := ipV4RE.FindStringSubmatch(fqdn)[1]
				match = strings.ReplaceAll(match, "-", ".")
				ipV4Address = net.ParseIP(match).To4()
				break
			}
		}
	}

	if ipV4Address == nil {
		return nil
	}

	return &dns.A{
		Hdr: dns.RR_Header{
			// Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
			Ttl:    uint32((time.Second * 10).Seconds()),
			Name:   fqdn,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: ipV4Address,
	}
}

func (xip *Xip) handleA(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	record := xip.fqdnToA(fqdn)

	if record == nil {
		message.Rcode = dns.RcodeNameError
		message.Ns = append(message.Ns, xip.SOARecord(question))
		return
	}

	log.Printf("(%s) %s => %s\n", flyRegion, fqdn, record.A)
	message.Answer = append(message.Answer, record)
}

func (xip *Xip) handleNS(question dns.Question, message *dns.Msg) {
	fqdn := question.Name
	nameServers := []*dns.NS{}
	additionals := []*dns.A{}
	for _, ns := range xip.NameServers {
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

		additionals = append(additionals, xip.fqdnToA(ns.Ns))
	}

	for _, record := range nameServers {
		message.Answer = append(message.Answer, record)
	}

	for _, record := range additionals {
		message.Extra = append(message.Extra, record)
	}
}

func (xip *Xip) SOARecord(question dns.Question) *dns.SOA {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:   question.Name,
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		// Ttl:      uint32((time.Hour * 24 * 7).Seconds()),
		Ttl:      uint32((time.Second * 10).Seconds()),
		Rdlength: 0,
	}
	soa.Ns = "ns.local-ip.sh."
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
		log.Printf("name: %s\n", question.Name)
		log.Printf("class: %d\n", question.Qclass)
		log.Printf("type: %d\n", question.Qtype)
		switch question.Qtype {
		case dns.TypeA:
			xip.handleA(question, message)
		case dns.TypeNS:
			xip.handleNS(question, message)
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
	log.Printf("Listening on %s\n", xip.Server.Addr)
	err := xip.Server.ListenAndServe()
	defer xip.Server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func NewXip(zone string, nameservers []string, port int) (xip *Xip) {
	xip = &Xip{}

	for _, ns := range nameservers {
		xip.NameServers = append(xip.NameServers, &dns.NS{Ns: ns})
	}

	xip.Server = dns.Server{
		Addr: ":" + strconv.Itoa(port),
		Net:  "udp",
	}

	dns.HandleFunc(zone, xip.handleDnsRequest)

	return xip
}
