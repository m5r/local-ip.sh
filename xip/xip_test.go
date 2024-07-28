package xip

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestResolveDashUnit(t *testing.T) {
	// viper.Set("dns-port", 9053)
	xip := NewXip()

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
	viper.Set("dns-port", 9053)
	xip := NewXip()

	if xip.nameServers[0] != "ns1.local-ip.sh" {
		t.Error("")
	}
	if xip.nameServers[1] != "ns2.local-ip.sh" {
		t.Error("")
	}
}

func TestResolveDashE2E(t *testing.T) {
	viper.Set("dns-port", 9053)
	xip := NewXip()
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
	// var semaphore = make(chan int, 40)
	// var done = make(chan bool, 1)

	for i := 0; i < b.N; i++ {
		port := 9053 + i
		viper.Set("dns-port", port)
		xip := NewXip()
		go xip.StartServer()

		// semaphore <- 1
		// go func() {
		cmd := exec.Command("dig", "@localhost", "-p", fmt.Sprint(port), "192-168-1-29.local-ip.sh", "+short")
		cmd.Run()

		// <-semaphore
		// if i == b.N {
		// done <- true
		// }
		// }()
	}
	// <-done
}
