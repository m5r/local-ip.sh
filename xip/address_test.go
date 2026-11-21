package xip

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddressIn(t *testing.T) {
	tests := []struct {
		name   string
		labels string
		want   string
	}{
		{name: "a dashed address", labels: "192-168-1-29.", want: "192.168.1.29"},
		{name: "a dotted address", labels: "192.168.1.29.", want: "192.168.1.29"},
		{name: "a dotted address after a label", labels: "prefixed.192.168.1.29.", want: "192.168.1.29"},
		{name: "a dotted address glued to text with a hyphen carries none", labels: "prefixed-192.168.1.29."},
		{name: "a dashed address with labels after it", labels: "192-168-1-29.app.", want: "192.168.1.29"},
		{name: "a dotted address with labels after it", labels: "192.168.1.29.app.", want: "192.168.1.29"},
		{name: "a dashed address after a label", labels: "app.10-0-0-1.", want: "10.0.0.1"},
		{name: "the apex carries none", labels: ""},
		{name: "labels without an address carry none", labels: "www.mail."},
		{name: "a dashed octet above 255 carries none", labels: "192-168-1-256."},
		{name: "a dotted octet above 255 carries none", labels: "192.168.256.1."},
		{name: "a dashed octet with a leading zero carries none", labels: "192-168-01-29."},
		{name: "a dotted octet with a leading zero carries none", labels: "192.168.01.29."},
		{name: "three dashed numbers carry none", labels: "192-168-1."},
		{name: "three dotted numbers carry none", labels: "192.168.1."},
		{name: "text glued before a dashed address carries none", labels: "prefixed-192-168-1-29."},
		{name: "text glued after a dashed address carries the address", labels: "192-168-1-29-app.", want: "192.168.1.29"},
		{name: "upper-case labels around a dashed address carry the address", labels: "APP.192-168-1-29.WWW.", want: "192.168.1.29"},
		{name: "upper-case labels around a dotted address carry the address", labels: "APP.192.168.1.29.WWW.", want: "192.168.1.29"},
		{name: "the dashed expression is tried before the dotted one", labels: "10.0.0.1.10-0-0-2.", want: "10.0.0.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, ok := addressIn(tt.labels)
			if ok != (tt.want != "") {
				t.Fatalf("addressIn(%q) = %v, %t; want %q", tt.labels, addr, ok, tt.want)
			}
			if ok && addr.String() != tt.want {
				t.Errorf("addressIn(%q) = %v, want %s", tt.labels, addr, tt.want)
			}
		})
	}
}

func TestAddressInLabelsBelowTheApexOnly(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		qname  string
		want   string
	}{
		{name: "a domain that carries an address gives no address to a name without one", domain: "10-0-0-1.example.test", qname: "app.10-0-0-1.example.test."},
		{name: "a domain that carries an address still resolves the address below it", domain: "10-0-0-1.example.test", qname: "10-0-0-2.10-0-0-1.example.test.", want: "10.0.0.2"},
		{name: "a domain that starts with a number does not complete three numbers below it", domain: "4.example.test", qname: "1.2.3.4.example.test."},
		{name: "a domain that starts with a number still resolves four numbers below it", domain: "4.example.test", qname: "9.1.2.3.4.example.test.", want: "9.1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := startTestServer(t,
				WithDomain(tt.domain),
				WithEmail("admin@example.test"),
				WithNameServers([]string{"192.0.2.10"}),
			)
			resp := queryTestServer(t, address, tt.qname, dns.TypeA)
			if tt.want == "" {
				if len(resp.Answer) != 0 {
					t.Errorf("got answers %q, want none", stringsOf(resp.Answer))
				}
				return
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want exactly 1:\n%s", len(resp.Answer), resp)
			}
			if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != tt.want {
				t.Errorf("answer = %q, want A %s", resp.Answer[0], tt.want)
			}
		})
	}
}
