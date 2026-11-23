package xip

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestConstructor(t *testing.T) {
	xip, err := NewXip(WithDomain("local-ip.sh"), withTestZone(t, ""))
	if err != nil {
		t.Fatal(err)
	}

	want := rrStrings(t, "local-ip.sh. 3600 IN NS ns1.local-ip.sh.", "local-ip.sh. 3600 IN NS ns2.local-ip.sh.")
	if got := stringsOf(xip.zone.records["local-ip.sh."][dns.TypeNS]); !slices.Equal(got, want) {
		t.Errorf("NS records = %q, want %q", got, want)
	}
}

func TestResolveDashE2E(t *testing.T) {
	address := startTestServer(t, WithDomain("resolve-dash.test"), withTestZone(t, ""))

	resp := queryTestServer(t, address, "192-168-1-29.resolve-dash.test.", dns.TypeA)

	if len(resp.Answer) != 1 {
		t.Fatalf("expected exactly one answer, received %d:\n%s", len(resp.Answer), resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected an A record, received %s", resp.Answer[0])
	}
	if a.A.String() != "192.168.1.29" {
		t.Fatalf("Expected 192.168.1.29 but received %s", a.A)
	}
}

// startTestServer serves a new instance on an ephemeral loopback port, over UDP and TCP, and returns its address.
func startTestServer(t *testing.T, opts ...Option) string {
	t.Helper()
	xip, err := NewXip(opts...)
	if err != nil {
		t.Fatalf("NewXip: %v", err)
	}
	return serveTestXip(t, xip)
}

// listenTestTransports binds a UDP socket and a TCP listener on the same ephemeral loopback port, the way the server is reached in production.
func listenTestTransports(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	// A port free for UDP can be taken for TCP by another process, so a few ports are tried.
	for range 20 {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("binding a loopback UDP socket: %v", err)
		}
		listener, err := net.Listen("tcp", conn.LocalAddr().String())
		if err == nil {
			return conn, listener
		}
		conn.Close()
	}
	t.Fatal("found no loopback port free for both UDP and TCP in 20 attempts")
	return nil, nil
}

// serveTestXip serves xip on an ephemeral loopback port, over UDP and TCP, until the test ends, then checks that Serve returned nil.
func serveTestXip(t *testing.T, xip *Xip) string {
	t.Helper()
	conn, listener := listenTestTransports(t)
	address := conn.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- xip.Serve(ctx, conn, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("Serve returned %v after cancellation, want nil", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return within 10 seconds of cancellation")
		}
	})
	return address
}

func queryTestServer(t *testing.T, address string, name string, qtype uint16) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	query.RecursionDesired = false
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, query, address)
	if err != nil {
		t.Fatalf("querying %s for %s %s: %v", address, name, dns.TypeToString[qtype], err)
	}
	return resp
}

// TestInstanceIsolation shows that each instance answers from its own zone: its own records, and a refusal for the other instance's names.
func TestInstanceIsolation(t *testing.T) {
	instances := []struct {
		domain, other, marker string
	}{
		{domain: "one.test", other: "two.test", marker: "one"},
		{domain: "two.test", other: "one.test", marker: "two"},
	}
	servers := make([]string, len(instances))
	for i, instance := range instances {
		servers[i] = startTestServer(t, WithDomain(instance.domain), withTestZone(t, fmt.Sprintf("marker TXT %q\n", instance.marker)))
	}

	for i, instance := range instances {
		t.Run(instance.domain+" answers from its own zone file", func(t *testing.T) {
			resp := queryTestServer(t, servers[i], "marker."+instance.domain+".", dns.TypeTXT)
			want := rrStrings(t, fmt.Sprintf("marker.%s. 300 IN TXT %q", instance.domain, instance.marker))
			if resp.Rcode != dns.RcodeSuccess || !slices.Equal(stringsOf(resp.Answer), want) {
				t.Errorf("want NOERROR and %q, received:\n%s", want, resp)
			}
		})
		t.Run(instance.domain+" refuses the names of "+instance.other, func(t *testing.T) {
			resp := queryTestServer(t, servers[i], "ns1."+instance.other+".", dns.TypeA)
			if resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 {
				t.Errorf("want REFUSED without answer, received:\n%s", resp)
			}
		})
	}
}

func newServeTestXip(t *testing.T, domain string, opts ...Option) *Xip {
	t.Helper()
	xip, err := NewXip(append([]Option{WithDomain(domain), withTestZone(t, "")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return xip
}

func TestServeStopsOnCancel(t *testing.T) {
	xip := newServeTestXip(t, "serve-cancel.test")
	conn, listener := listenTestTransports(t)
	address := conn.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- xip.Serve(ctx, conn, listener) }()

	for _, network := range []string{"udp", "tcp"} {
		resp := exchangeOver(t, network, address, ask("ns1.serve-cancel.test.", dns.TypeA))
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers over %s before cancellation, want 1:\n%s", len(resp.Answer), network, resp)
		}
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after cancellation, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10 seconds of cancellation")
	}

	rebound, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("binding %s over UDP again after Serve returned: %v", address, err)
	}
	if err := rebound.Close(); err != nil {
		t.Error(err)
	}
	relistened, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listening on %s over TCP again after Serve returned: %v", address, err)
	}
	if err := relistened.Close(); err != nil {
		t.Error(err)
	}
}

func TestServeRequiresBothTransports(t *testing.T) {
	xip := newServeTestXip(t, "serve-both.test")
	conn, listener := listenTestTransports(t)
	address := conn.LocalAddr().String()
	listener.Close()
	if err := xip.Serve(t.Context(), conn, nil); err == nil {
		t.Fatal("Serve without a TCP listener returned nil, want an error")
	}
	rebound, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("the UDP socket is still bound after Serve refused to start: %v", err)
	}
	rebound.Close()
}

func TestServeReportsReadLoopError(t *testing.T) {
	xip := newServeTestXip(t, "serve-error.test")
	conn, listener := listenTestTransports(t)

	served := make(chan error, 1)
	go func() { served <- xip.Serve(t.Context(), conn, listener) }()

	// An answered query proves the read loop is running, so the close below hits the loop and not the start.
	queryTestServer(t, conn.LocalAddr().String(), "ns1.serve-error.test.", dns.TypeA)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-served:
		if err == nil || !strings.Contains(err.Error(), "over UDP") {
			t.Fatalf("Serve returned %v after its socket was closed from outside, want an error naming UDP", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10 seconds of its socket being closed")
	}
}

func TestTwoInstancesSameZone(t *testing.T) {
	const domain = "same-zone.test"
	addresses := map[string]string{}
	for _, www := range []string{"192.0.2.1", "192.0.2.2"} {
		addresses[www] = startTestServer(t, WithDomain(domain), withTestZone(t, "www A "+www+"\n"))
	}

	for www, address := range addresses {
		resp := queryTestServer(t, address, "www."+domain+".", dns.TypeA)
		if len(resp.Answer) != 1 {
			t.Errorf("server with %s: got %d answers, want 1:\n%s", www, len(resp.Answer), resp)
			continue
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != www {
			t.Errorf("server with %s answered %q, want the address of its own zone file", www, resp.Answer[0])
		}
	}
}

func TestNewXipValidation(t *testing.T) {
	zone := withTestZone(t, "")
	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{name: "no domain", opts: []Option{zone}, wantErr: `xip: invalid domain "": empty`},
		{name: "invalid domain", opts: []Option{WithDomain("a..b"), zone}, wantErr: `xip: invalid domain "a..b": empty label`},
		{name: "domain that is an address", opts: []Option{WithDomain("192.0.2.1"), zone}, wantErr: `xip: invalid domain "192.0.2.1": an IP address`},
		{name: "no zone file", opts: []Option{WithDomain("validation.test")}, wantErr: "xip: a zone file is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xip, err := NewXip(tt.opts...)
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("NewXip error = %v, want %q", err, tt.wantErr)
			}
			if xip != nil {
				t.Error("NewXip returned a server together with an error")
			}
		})
	}

	t.Run("domain in canonical form", func(t *testing.T) {
		xip, err := NewXip(WithDomain("Example.COM."), zone)
		if err != nil {
			t.Fatal(err)
		}
		if xip.domain != "example.com" {
			t.Errorf("domain = %q, want example.com", xip.domain)
		}
		if err := xip.AddChallenge("_acme-challenge.example.com", "token"); err != nil {
			t.Errorf("AddChallenge at the canonical challenge name: %v", err)
		}
		address := serveTestXip(t, xip)

		resp := queryTestServer(t, address, "ns1.example.com.", dns.TypeA)
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers, want 1:\n%s", len(resp.Answer), resp)
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.Hdr.Name != "ns1.example.com." || a.A.String() != "192.0.2.10" {
			t.Errorf("answer = %q, want ns1.example.com. A 192.0.2.10", resp.Answer[0])
		}
		ns := queryTestServer(t, address, "example.com.", dns.TypeNS)
		want := rrStrings(t, "example.com. 3600 IN NS ns1.example.com.", "example.com. 3600 IN NS ns2.example.com.")
		if !slices.Equal(stringsOf(ns.Answer), want) {
			t.Errorf("NS answer = %q, want %q", stringsOf(ns.Answer), want)
		}
		txt := queryTestServer(t, address, "_acme-challenge.example.com.", dns.TypeTXT)
		if len(txt.Answer) != 1 {
			t.Errorf("challenge TXT: got %d answers, want 1:\n%s", len(txt.Answer), txt)
		}
	})
}
