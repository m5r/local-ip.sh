package app

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// WriteTestZone writes a zone file with the records every zone needs and returns its path. It is exported for the tests of package app_test.
func WriteTestZone(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zone")
	content := "@ 3600 SOA ns1 admin 1 900 900 1800 3600\n@ 3600 NS ns1\nns1 3600 A 192.0.2.53\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunEndsWhenDNSStops(t *testing.T) {
	a, err := New(Config{
		Domain:        "app.test",
		ZoneFile:      WriteTestZone(t),
		Email:         "admin@app.test",
		DNSUDPAddress: "127.0.0.1:0",
		DNSTCPAddress: "127.0.0.1:0",
		HTTPAddress:   "127.0.0.1:0",
		HTTPSAddress:  "127.0.0.1:0",
		StateDir:      t.TempDir(),
		// Nothing listens there: the manager's orders fail, which must not matter.
		DirectoryURL: "https://127.0.0.1:1/dir",
		ACMEProfile:  "default",
		Logger:       zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// An answer shows the read loop runs, so that what follows tests a loop that ends, not one that never started.
	message := new(dns.Msg)
	message.SetQuestion("10-0-0-1.app.test.", dns.TypeA)
	if _, _, err := (&dns.Client{Net: "udp", Timeout: 5 * time.Second}).Exchange(message, a.DNSUDPAddr().String()); err != nil {
		t.Fatalf("the DNS server does not answer: %v", err)
	}

	httpAddress := a.HTTPAddr().String()
	a.dnsConn.Close()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "DNS server") {
			t.Errorf("Run returned %v, want an error naming the DNS server", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the DNS socket was closed")
	}

	listener, err := net.Listen("tcp", httpAddress)
	if err != nil {
		t.Fatalf("the HTTP port is still bound after Run returned: %v", err)
	}
	listener.Close()
}
