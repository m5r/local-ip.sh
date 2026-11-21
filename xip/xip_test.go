package xip

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestConstructor(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithEmail("admin@local-ip.sh"),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"ns1.local-ip.sh.", "ns2.local-ip.sh."}
	if !slices.Equal(xip.zone.nameServers, want) {
		t.Errorf("name servers = %q, want %q", xip.zone.nameServers, want)
	}
}

func TestResolveDashE2E(t *testing.T) {
	address := startTestServer(t,
		WithDomain("resolve-dash.test"),
		WithEmail("admin@resolve-dash.test"),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)

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

// startTestServer serves a new instance on an ephemeral loopback UDP port and returns its address.
func startTestServer(t *testing.T, opts ...Option) string {
	t.Helper()
	xip, err := NewXip(opts...)
	if err != nil {
		t.Fatalf("NewXip: %v", err)
	}
	return serveTestXip(t, xip)
}

// serveTestXip serves xip on an ephemeral loopback UDP port until the test ends, then checks that Serve returned nil.
func serveTestXip(t *testing.T, xip *Xip) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding a loopback UDP socket: %v", err)
	}
	address := conn.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- xip.Serve(ctx, conn) }()
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

// TestInstanceIsolation shows that each instance answers from its own zone: its own name server address, and a refusal for the other instance's names.
func TestInstanceIsolation(t *testing.T) {
	instances := []struct {
		domain, other, address string
	}{
		{domain: "one.test", other: "two.test", address: "1.1.1.1"},
		{domain: "two.test", other: "one.test", address: "2.2.2.2"},
	}
	servers := make([]string, len(instances))
	for i, instance := range instances {
		servers[i] = startTestServer(t,
			WithDomain(instance.domain),
			WithEmail("admin@"+instance.domain),
			WithNameServers([]string{instance.address}),
		)
	}

	for i, instance := range instances {
		t.Run(instance.domain+" answers for its own name server", func(t *testing.T) {
			resp := queryTestServer(t, servers[i], "ns1."+instance.domain+".", dns.TypeA)
			want := rrStrings(t, "ns1."+instance.domain+". 300 IN A "+instance.address)
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

func TestServeStopsOnCancel(t *testing.T) {
	xip, err := NewXip(
		WithDomain("serve-cancel.test"),
		WithEmail("admin@serve-cancel.test"),
		WithNameServers([]string{"192.0.2.10"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- xip.Serve(ctx, conn) }()

	resp := queryTestServer(t, address, "ns1.serve-cancel.test.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers before cancellation, want 1:\n%s", len(resp.Answer), resp)
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
		t.Fatalf("binding %s again after Serve returned: %v", address, err)
	}
	if err := rebound.Close(); err != nil {
		t.Error(err)
	}
}

func TestServeReportsReadLoopError(t *testing.T) {
	xip, err := NewXip(
		WithDomain("serve-error.test"),
		WithEmail("admin@serve-error.test"),
		WithNameServers([]string{"192.0.2.10"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	served := make(chan error, 1)
	go func() { served <- xip.Serve(t.Context(), conn) }()

	// An answered query proves the read loop is running, so the close below hits the loop and not the start.
	queryTestServer(t, conn.LocalAddr().String(), "ns1.serve-error.test.", dns.TypeA)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-served:
		if err == nil {
			t.Fatal("Serve returned nil after its socket was closed from outside, want an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10 seconds of its socket being closed")
	}
}

func TestTwoInstancesSameZone(t *testing.T) {
	const domain = "same-zone.test"
	addresses := map[string]string{}
	for _, ns := range []string{"192.0.2.1", "192.0.2.2"} {
		addresses[ns] = startTestServer(t,
			WithDomain(domain),
			WithEmail("admin@"+domain),
			WithNameServers([]string{ns}),
		)
	}

	for ns, address := range addresses {
		resp := queryTestServer(t, address, "ns1."+domain+".", dns.TypeA)
		if len(resp.Answer) != 1 {
			t.Errorf("server with %s: got %d answers, want 1:\n%s", ns, len(resp.Answer), resp)
			continue
		}
		if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != ns {
			t.Errorf("server with %s answered %q, want its own address", ns, resp.Answer[0])
		}
	}
}

func TestNewXipValidation(t *testing.T) {
	valid := []Option{
		WithDomain("validation.test"),
		WithEmail("admin@validation.test"),
		WithNameServers([]string{"192.0.2.10"}),
	}
	with := func(opts ...Option) []Option {
		return append(slices.Clone(valid), opts...)
	}

	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{name: "no domain", opts: []Option{WithEmail("admin@validation.test"), WithNameServers([]string{"192.0.2.10"})}, wantErr: `xip: invalid domain "": empty`},
		{name: "invalid domain", opts: with(WithDomain("a..b")), wantErr: `xip: invalid domain "a..b": empty label`},
		{name: "domain that is an address", opts: with(WithDomain("192.0.2.1")), wantErr: `xip: invalid domain "192.0.2.1": an IP address`},
		{name: "no email", opts: []Option{WithDomain("validation.test"), WithNameServers([]string{"192.0.2.10"})}, wantErr: `xip: email "" is not a bare address`},
		{name: "email that is not an address", opts: with(WithEmail("admin")), wantErr: `xip: email "admin" is not a bare address`},
		{name: "email with a display name", opts: with(WithEmail("Admin <admin@validation.test>")), wantErr: `xip: email "Admin <admin@validation.test>" is not a bare address`},
		{name: "email in angle brackets", opts: with(WithEmail("<admin@validation.test>")), wantErr: `xip: email "<admin@validation.test>" is not a bare address`},
		{name: "no name server", opts: []Option{WithDomain("validation.test"), WithEmail("admin@validation.test")}, wantErr: "xip: at least one name server is required"},
		{name: "empty name server list", opts: with(WithNameServers(nil)), wantErr: "xip: at least one name server is required"},
		{name: "IPv6 name server", opts: with(WithNameServers([]string{"192.0.2.10", "2001:db8::1"})), wantErr: `xip: name server "2001:db8::1" is not an IPv4 address`},
		{name: "IPv4-mapped IPv6 name server", opts: with(WithNameServers([]string{"::ffff:192.0.2.10"})), wantErr: `xip: name server "::ffff:192.0.2.10" is not an IPv4 address`},
		{name: "name server that is a host name", opts: with(WithNameServers([]string{"ns.example.test"})), wantErr: `xip: name server "ns.example.test" is not an IPv4 address`},
		{name: "empty name server", opts: with(WithNameServers([]string{""})), wantErr: `xip: name server "" is not an IPv4 address`},
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
		xip, err := NewXip(
			WithDomain("Example.COM."),
			WithEmail("admin@example.com"),
			WithNameServers([]string{"192.0.2.10"}),
		)
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
		want := rrStrings(t, "example.com. 300 IN NS ns1.example.com.")
		if !slices.Equal(stringsOf(ns.Answer), want) {
			t.Errorf("NS answer = %q, want %q", stringsOf(ns.Answer), want)
		}
		txt := queryTestServer(t, address, "_acme-challenge.example.com.", dns.TypeTXT)
		if len(txt.Answer) != 1 {
			t.Errorf("challenge TXT: got %d answers, want 1:\n%s", len(txt.Answer), txt)
		}
	})
}
