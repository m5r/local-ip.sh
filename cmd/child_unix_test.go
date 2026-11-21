//go:build unix

package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// childWait bounds every wait on a child process, so that a hang fails the test instead of blocking the run.
const childWait = 10 * time.Second

// child is the test binary started again to run one test function as a separate process.
type child struct {
	process *exec.Cmd
	// stdin is nil unless the child was started with input.
	stdin  io.WriteCloser
	output *lineWriter
	stderr bytes.Buffer
	// exited is closed once Wait has returned, with its result in exitErr; Wait runs from the start, so the child is always reaped, whichever way the test ends.
	exited  chan struct{}
	exitErr error
}

// startChild runs the test function named run in a new process of the test binary, with environmentFlag set to 1 so that the function knows it is the child. At the end of the test the child is killed if it still runs, and reaped.
func startChild(t *testing.T, run, environmentFlag string, withInput bool) *child {
	t.Helper()
	c := &child{
		process: exec.Command(os.Args[0], "-test.run=^"+run+"$"),
		output:  &lineWriter{lines: make(chan string, 64)},
		exited:  make(chan struct{}),
	}
	c.process.Env = append(os.Environ(), environmentFlag+"=1")
	c.process.Stdout = c.output
	c.process.Stderr = &c.stderr
	if withInput {
		stdin, err := c.process.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		c.stdin = stdin
	}
	if err := c.process.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		c.exitErr = c.process.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() {
		c.process.Process.Kill()
		select {
		case <-c.exited:
		case <-time.After(childWait):
			t.Errorf("the child was not reaped within %v of being killed", childWait)
		}
		if t.Failed() {
			t.Logf("standard error of the child:\n%s", c.stderr.String())
		}
	})
	return c
}

// expect fails the test unless the next line the child prints is want.
func (c *child) expect(t *testing.T, want string) {
	t.Helper()
	select {
	case line := <-c.output.lines:
		if line != want {
			t.Fatalf("the child printed %q, want %q", line, want)
		}
	case <-c.exited:
		t.Fatalf("the child exited with %v while the test waited for %q", c.exitErr, want)
	case <-time.After(childWait):
		t.Fatalf("the child did not print %q within %v", want, childWait)
	}
}

func (c *child) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
		t.Fatalf("writing %q to the child: %v", line, err)
	}
}

func (c *child) signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := c.process.Process.Signal(sig); err != nil {
		t.Fatalf("sending %v to the child: %v", sig, err)
	}
}

// wait returns the result of the child's Wait, and fails the test when the child does not exit in time.
func (c *child) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-c.exited:
		return c.exitErr
	case <-time.After(childWait):
		t.Fatalf("the child did not exit within %v", childWait)
		return nil
	}
}

// lineWriter hands every complete line written to it to a channel. As the standard output of a child, it is fed by a goroutine of exec.Cmd that Wait waits for, so the output is complete once Wait returns; a line nobody reads once the channel is full is dropped rather than blocking that goroutine, which would block Wait.
type lineWriter struct {
	mu      sync.Mutex
	partial bytes.Buffer
	lines   chan string
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.partial.Write(p)
	for {
		line, err := w.partial.ReadString('\n')
		if err != nil {
			w.partial.WriteString(line)
			return len(p), nil
		}
		select {
		case w.lines <- strings.TrimSuffix(line, "\n"):
		default:
		}
	}
}

// endedBy fails the test unless err says the child was ended by sig.
func endedBy(t *testing.T, err error, sig syscall.Signal) {
	t.Helper()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("the child exited with %v, want to be ended by %v", err, sig)
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != sig {
		t.Fatalf("the child ended with %v, want to be ended by %v", exitError, sig)
	}
}
