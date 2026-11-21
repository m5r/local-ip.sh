//go:build unix

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
)

const renewSignalChildEnv = "LOCAL_IP_RENEW_SIGNAL_CHILD"

// TestRenewSignal runs onRenewSignal in a child process, so that the signals are sent to a real process whose exit status is checked, and the test binary's own signal handling stays out of it.
func TestRenewSignal(t *testing.T) {
	c := startChild(t, "TestRenewSignalChild", renewSignalChildEnv, true)

	c.expect(t, "ready")
	c.signal(t, syscall.SIGUSR1)
	c.expect(t, "renewed")
	c.signal(t, syscall.SIGUSR1)
	c.expect(t, "renewed")
	c.send(t, "cancel")
	c.expect(t, "cancelled")
	c.signal(t, syscall.SIGUSR1)
	c.send(t, "ping")
	c.expect(t, "pong")
	if err := c.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.wait(t); err != nil {
		t.Fatalf("the child exited with %v, want status 0", err)
	}
}

// TestRenewSignalChild is the child process of TestRenewSignal; it is skipped in an ordinary run.
func TestRenewSignalChild(t *testing.T) {
	if os.Getenv(renewSignalChildEnv) == "" {
		t.Skip("runs only as the child process of TestRenewSignal")
	}
	var output sync.Mutex
	println := func(line string) {
		output.Lock()
		defer output.Unlock()
		fmt.Fprintln(os.Stdout, line)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	onRenewSignal(ctx, zerolog.Nop(), func() { println("renewed") })
	println("ready")

	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		switch command := input.Text(); command {
		case "cancel":
			cancel()
			println("cancelled")
		case "ping":
			println("pong")
		default:
			t.Fatalf("unknown command %q", command)
		}
	}
	if err := input.Err(); err != nil {
		t.Fatal(err)
	}
}
