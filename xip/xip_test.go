package xip

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolveDashUnit(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithEmail("admin@local-ip.sh"),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	A := xip.fqdnToA("192-168-1-29.local-ip.sh")
	expected := "192.168.1.29"
	received := A[0].A.String()
	if received != expected {
		t.Fatalf("Expected %s but received %s", expected, received)
	}

	A = xip.fqdnToA("192.168.1.29.local-ip.sh")
	expected = "192.168.1.29"
	received = A[0].A.String()
	if received != expected {
		t.Fatalf("Expected %s but received %s", expected, received)
	}

	A = xip.fqdnToA("prefixed.192.168.1.29.local-ip.sh")
	expected = "192.168.1.29"
	received = A[0].A.String()
	if received != expected {
		t.Fatalf("Expected %s but received %s", expected, received)
	}

	A = xip.fqdnToA("prefixed-192.168.1.29.local-ip.sh")
	if A != nil {
		t.Fatalf("Expected %v but received %s", nil, A)
	}
}

func TestResolveLabelsAfterAddress(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithEmail("admin@local-ip.sh"),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"192-168-1-29.app.local-ip.sh", "192.168.1.29.app.local-ip.sh"} {
		t.Run(name, func(t *testing.T) {
			records := xip.fqdnToA(name)
			if len(records) != 1 {
				t.Fatalf("got %d A records, want 1: %v", len(records), records)
			}
			if got, want := records[0].A.String(), "192.168.1.29"; got != want {
				t.Errorf("A = %s, want %s", got, want)
			}
		})
	}
}

func TestConstructor(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithEmail("admin@local-ip.sh"),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	if xip.nameServers[0] != "ns1.local-ip.sh." {
		t.Errorf("expected ns1.local-ip.sh., got %s", xip.nameServers[0])
	}
	if xip.nameServers[1] != "ns2.local-ip.sh." {
		t.Errorf("expected ns2.local-ip.sh., got %s", xip.nameServers[1])
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

func TestInstanceIsolation(t *testing.T) {
	xip1, err := NewXip(
		WithDomain("one.test"),
		WithEmail("admin@one.test"),
		WithNameServers([]string{"1.1.1.1"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	xip2, err := NewXip(
		WithDomain("two.test"),
		WithEmail("admin@two.test"),
		WithNameServers([]string{"2.2.2.2"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	if xip1.records == nil || xip2.records == nil {
		t.Fatal("records not initialized")
	}

	if len(xip1.nameServers) != 1 || xip1.nameServers[0] != "ns1.one.test." {
		t.Errorf("xip1 nameservers incorrect: %v", xip1.nameServers)
	}
	if len(xip2.nameServers) != 1 || xip2.nameServers[0] != "ns1.two.test." {
		t.Errorf("xip2 nameservers incorrect: %v", xip2.nameServers)
	}

	if _, ok := xip1.records["ns1.one.test."]; !ok {
		t.Error("xip1 missing ns1.one.test. record")
	}
	if _, ok := xip2.records["ns1.two.test."]; !ok {
		t.Error("xip2 missing ns1.two.test. record")
	}

	if _, ok := xip1.records["ns1.two.test."]; ok {
		t.Error("xip1 should not have xip2's records")
	}
	if _, ok := xip2.records["ns1.one.test."]; ok {
		t.Error("xip2 should not have xip1's records")
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
