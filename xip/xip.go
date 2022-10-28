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
	flyRegion       = os.Getenv("FLY_REGION")
	dottedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})($|[.-])`)
	dashedIpV4Regex = regexp.MustCompile(`(?:^|(?:[\w\d])+\.)(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4})($|[.-])`)
)

func (xip *Xip) handleA(question dns.Question, response *dns.Msg) *dns.A {
	fqdn := question.Name

	for _, ipV4RE := range []*regexp.Regexp{dashedIpV4Regex, dottedIpV4Regex} {
		if ipV4RE.MatchString(fqdn) {
			match := ipV4RE.FindStringSubmatch(fqdn)[1]
			match = strings.ReplaceAll(match, "-", ".")
			ipV4Address := net.ParseIP(match).To4()
			if ipV4Address == nil {
				return nil
			}

			resource := &dns.A{
				Hdr: dns.RR_Header{
					Ttl:    uint32((time.Hour * 24 * 7).Seconds()),
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: ipV4Address,
			}
			log.Printf("(%s) %s => %s\n", flyRegion, fqdn, ipV4Address)
			return resource
		}
	}

	return nil
}

func (xip *Xip) handleQuery(message *dns.Msg) {
	for _, question := range message.Question {
		switch question.Qtype {
		case dns.TypeA:
			record := xip.handleA(question, message)
			message.Answer = append(message.Answer, record)
		}
	}
}

func (xip *Xip) refuseMessage(message *dns.Msg) {
	message.MsgHdr.Rcode = dns.RcodeRefused

	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:     "my.local-ip.dev.",
		Rrtype:   dns.TypeSOA,
		Class:    dns.ClassINET,
		Ttl:      uint32((time.Hour * 24 * 7).Seconds()),
		Rdlength: 0,
	}
	soa.Ns = "ns.local-ip.dev."
	soa.Mbox = "admin.local-ip.dev."
	soa.Serial = 2022102800
	soa.Refresh = uint32((time.Minute * 15).Seconds())
	soa.Retry = uint32((time.Minute * 15).Seconds())
	soa.Expire = uint32((time.Minute * 30).Seconds())
	soa.Minttl = uint32((time.Minute * 5).Seconds())
	message.Ns = append(message.Ns, soa)
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
			xip.refuseMessage(message)
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
