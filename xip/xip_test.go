package xip

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestResolveDashUnit(t *testing.T) {
	xip := NewXip(
		WithDomain("local-ip.sh"),
		WithDnsPort(9053),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)

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
	xip := NewXip(
		WithDomain("local-ip.sh"),
		WithDnsPort(9053),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)

	if xip.nameServers[0] != "ns1.local-ip.sh." {
		t.Errorf("expected ns1.local-ip.sh., got %s", xip.nameServers[0])
	}
	if xip.nameServers[1] != "ns2.local-ip.sh." {
		t.Errorf("expected ns2.local-ip.sh., got %s", xip.nameServers[1])
	}
}

func TestResolveDashE2E(t *testing.T) {
	xip := NewXip(
		WithDomain("local-ip.sh"),
		WithDnsPort(9053),
		WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
	)
	go xip.StartServer()

	cmd := exec.Command("dig", "@localhost", "-p", "9053", "192-168-1-29.local-ip.sh", "+short")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(string(out)) != "192.168.1.29" {
		t.Fatal(string(out))
	}
}

func BenchmarkResolveDashBasic(b *testing.B) {
	b.Skip()

	for i := 0; i < b.N; i++ {
		port := 9053 + i
		xip := NewXip(
			WithDomain("local-ip.sh"),
			WithDnsPort(uint(port)),
			WithNameServers([]string{"1.2.3.4", "5.6.7.8"}),
		)
		go xip.StartServer()

		cmd := exec.Command("dig", "@localhost", "-p", fmt.Sprint(port), "192-168-1-29.local-ip.sh", "+short")
		cmd.Run()
	}
}
