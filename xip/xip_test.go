package xip

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolveDashUnit(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithDnsPort(9053),
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

func TestConstructor(t *testing.T) {
	xip, err := NewXip(
		WithDomain("local-ip.sh"),
		WithDnsPort(9053),
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

// startTestServer starts a server on an ephemeral loopback UDP port and returns its address. The
// handler is registered on the process-wide default mux keyed by zone, so every caller must use a
// domain no other test uses, and must set an email because negative answers build an SOA from it.
func startTestServer(t *testing.T, opts ...Option) string {
	t.Helper()
	xip, err := NewXip(append([]Option{WithDnsPort(0)}, opts...)...)
	if err != nil {
		t.Fatalf("NewXip: %v", err)
	}
	if xip.email == "" {
		t.Fatal("test servers need WithEmail: negative answers panic on an empty email")
	}

	started := make(chan struct{})
	xip.server.NotifyStartedFunc = func() { close(started) }
	go xip.StartServer()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("DNS server did not start within 5 seconds")
	}
	t.Cleanup(func() {
		if err := xip.server.Shutdown(); err != nil {
			t.Errorf("shutting down DNS server: %v", err)
		}
	})

	port := xip.server.PacketConn.LocalAddr().(*net.UDPAddr).Port
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
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
		WithDnsPort(0),
		WithNameServers([]string{"1.1.1.1"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	xip2, err := NewXip(
		WithDomain("two.test"),
		WithDnsPort(0),
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
