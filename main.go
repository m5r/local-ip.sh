package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const zone = "my.local-ip.dev."

func main() {
	dns.HandleFunc(zone, handleDnsRequest)

	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		port = 9053
	}
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(port),
		Net:  "udp",
	}
	log.Printf("Starting at %d\n", port)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func handleDnsRequest(response dns.ResponseWriter, request *dns.Msg) {
	go func() {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Compress = true

		switch request.Opcode {
		case dns.OpcodeQuery:
			handleQuery(message)
		default:
			refuseMessage(message)
		}

		response.WriteMsg(message)
	}()
}

func handleQuery(message *dns.Msg) {
	for _, question := range message.Question {
		switch question.Qtype {
		case dns.TypeA:
			ip := extractIp(question.Name)
			log.Printf("%s => %s\n", question.Name, ip)
			if ip == nil {
				refuseMessage(message)
				break
			}

			resource := new(dns.A)
			resource.Hdr = dns.RR_Header{Ttl: 10, Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}
			resource.A = ip
			message.Answer = append(message.Answer, resource)
		}
	}
}

func extractIp(fqdn string) net.IP {
	var ip string
	dashedIpRegex := regexp.MustCompile(fmt.Sprintf(`^(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\-?\b){4}).%s$`, zone))
	matches := dashedIpRegex.FindStringSubmatch(fqdn)
	if len(matches) < 2 {
		return nil
	}

	ip = strings.ReplaceAll(matches[1], "-", ".")

	return net.ParseIP(ip)
}

func refuseMessage(message *dns.Msg) {
	message.MsgHdr.Rcode = dns.RcodeRefused

	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:     "my.local-ip.dev.",
		Rrtype:   dns.TypeSOA,
		Class:    dns.ClassINET,
		Ttl:      10,
		Rdlength: 0,
	}
	soa.Ns = "ns-1.local-ip.dev."
	soa.Mbox = "admin.local-ip.dev."
	soa.Serial = 2022102400
	soa.Refresh = 10
	soa.Retry = 10
	soa.Expire = 10
	soa.Minttl = 10
	message.Ns = append(message.Ns, soa)
}
