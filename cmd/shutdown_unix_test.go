//go:build unix

package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

const shutdownSignalChildEnv = "LOCAL_IP_SHUTDOWN_SIGNAL_CHILD"

// TestShutdownSignal runs shutdownContext in a child process: a second signal must end a process whose shutdown hangs, and only a real process whose end can be observed shows that.
func TestShutdownSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			// A process started with SIGINT ignored keeps it ignored once the last registration is released, and its child inherits that, so there is no second-SIGINT escape to observe; SIGTERM has no such exception.
			if sig == syscall.SIGINT && signal.Ignored(syscall.SIGINT) {
				t.Skip("the test binary was started with SIGINT ignored, so a second SIGINT cannot end the child")
			}
			c := startChild(t, "TestShutdownSignalChild", shutdownSignalChildEnv, false)
			c.expect(t, "ready")
			c.signal(t, sig)
			c.expect(t, "cancelled")

			// AfterFunc releases the registration from a goroutine of its own, so a signal sent right after "cancelled" may still be caught and dropped: the second signal is repeated until the child ends.
			repeat := time.NewTicker(50 * time.Millisecond)
			defer repeat.Stop()
			deadline := time.After(childWait)
			for {
				c.process.Process.Signal(sig)
				select {
				case <-c.exited:
					endedBy(t, c.exitErr, sig)
					return
				case <-repeat.C:
				case <-deadline:
					t.Fatalf("the child was not ended by a second %v within %v", sig, childWait)
				}
			}
		})
	}
}

// TestShutdownSignalChild is the child process of TestShutdownSignal; it is skipped in an ordinary run. Its shutdown hangs for ever once the first signal has arrived.
func TestShutdownSignalChild(t *testing.T) {
	if os.Getenv(shutdownSignalChildEnv) == "" {
		t.Skip("runs only as the child process of TestShutdownSignal")
	}
	ctx, stop := shutdownContext()
	defer stop()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("cancelled")
	select {}
}
