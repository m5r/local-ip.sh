package xip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// advertisedUDPSize is the largest UDP reply the server sends and the size its OPT record advertises: the value of DNS flag day 2020, small enough to cross common paths without IP fragmentation.
const advertisedUDPSize = 1232

// optRecordLength is the length in wire format of the OPT record the server adds to a reply: the root name and the fixed fields, without options.
const optRecordLength = 11

// The limits of a TCP connection. The read timeouts and the query count are the library's defaults, set here so that they do not change with it; the library has no cap on connections and sets no write deadline.
const (
	maxTCPConnections = 256
	tcpReadTimeout    = 2 * time.Second
	tcpIdleTimeout    = 8 * time.Second
	maxTCPQueries     = 128
	tcpWriteTimeout   = 2 * time.Second
)

// shutdownTimeout bounds how long ShutdownContext waits for the handlers in flight once Serve has asked both servers to stop. Serve then still waits for the read loops to return, without a timeout of its own: see shutdown.
const shutdownTimeout = 2 * time.Second

// headerQR is the QR bit of a header's flags, which the library does not export.
const headerQR = 1 << 15

// ednsOf returns the last OPT record of the additional section of request and the number of OPT records there.
func ednsOf(request *dns.Msg) (opt *dns.OPT, count int) {
	for _, rr := range request.Extra {
		if record, ok := rr.(*dns.OPT); ok {
			opt = record
			count++
		}
	}
	return opt, count
}

// replyOPT is the OPT record of every reply to a query with EDNS: version 0, no options, and the DO bit of the query, as RFC 3225 asks even of a server without DNSSEC.
func replyOPT(do bool) *dns.OPT {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(advertisedUDPSize)
	if do {
		opt.SetDo()
	}
	return opt
}

// replyLimit is the size a reply must fit in on the transport of local, given the OPT record of the query (nil for none). A TCP reply is bounded by the length field alone, whatever the query advertises.
func replyLimit(local net.Addr, queryOPT *dns.OPT) int {
	switch {
	case local.Network() == "tcp":
		return dns.MaxMsgSize
	case queryOPT == nil:
		return dns.MinMsgSize
	}
	return min(max(int(queryOPT.UDPSize()), dns.MinMsgSize), advertisedUDPSize)
}

// acceptMessage hands every message the library reads to the handler, where the library's default would refuse some by itself with replies that repeat the request's flags. A response gets no reply at all: replying to responses is how two servers start answering each other forever.
// A message whose body does not unpack still gets the library's own FORMERR, built before any hook runs: replacing it would take a read loop of our own, and it is a valid FORMERR.
func acceptMessage(header dns.Header) dns.MsgAcceptAction {
	if header.Bits&headerQR != 0 {
		return dns.MsgIgnore
	}
	return dns.MsgAccept
}

// Serve answers the queries arriving on conn over UDP and on listener over TCP until ctx is cancelled, then stops reading, waits for the handlers in flight and returns nil.
// If either read loop stops by itself, Serve stops the other one and returns the error. It takes ownership of conn and listener and closes both in every case.
func (xip *Xip) Serve(ctx context.Context, conn net.PacketConn, listener net.Listener) error {
	// The servers close what they serve on most paths but not when ActivateAndServe fails before reading, and a second Close is harmless.
	if conn != nil {
		defer conn.Close()
	}
	if listener != nil {
		defer listener.Close()
	}
	if conn == nil || listener == nil {
		return errors.New("xip: serve: a UDP socket and a TCP listener are both required")
	}

	handler := dns.HandlerFunc(xip.handleDnsRequest)
	bounded := newBoundedListener(listener, maxTCPConnections)
	udp := &transport{name: "UDP", address: conn.LocalAddr(), server: &dns.Server{
		PacketConn:    conn,
		Handler:       handler,
		UDPSize:       advertisedUDPSize,
		MsgAcceptFunc: acceptMessage,
	}}
	tcp := &transport{name: "TCP", address: listener.Addr(), server: &dns.Server{
		Listener:      bounded,
		Handler:       handler,
		MsgAcceptFunc: acceptMessage,
		ReadTimeout:   tcpReadTimeout,
		IdleTimeout:   func() time.Duration { return tcpIdleTimeout },
		MaxTCPQueries: maxTCPQueries,
	}}
	transports := []*transport{udp, tcp}

	for _, t := range transports {
		t.start()
	}
	// Shutdown refuses a server that has not started, so the context is only watched once both read loops run.
	var startErr error
	for _, t := range transports {
		select {
		case <-t.started:
		case err := <-t.served:
			t.ended = true
			startErr = errors.Join(startErr, t.failure(err))
		}
	}
	if startErr != nil {
		return errors.Join(startErr, xip.shutdown(ctx, transports))
	}
	for _, t := range transports {
		xip.logger.Info().Str("dns_address", t.address.String()).Str("transport", t.name).Msg("Starting up DNS server")
	}

	var cause error
	select {
	case <-ctx.Done():
	case err := <-udp.served:
		udp.ended = true
		cause = udp.stoppedByItself(err)
	case err := <-tcp.served:
		tcp.ended = true
		cause = tcp.stoppedByItself(err)
	case err := <-bounded.failed:
		cause = tcp.failure(err)
	}
	shutdownErr := xip.shutdown(ctx, transports)
	if cause != nil {
		// The other loop's return after the shutdown, and the TCP loop's echo of the accept error, add nothing to the cause.
		return cause
	}
	return shutdownErr
}

// transport is one of the two servers Serve runs, with what Serve needs to follow it.
type transport struct {
	name    string
	address net.Addr
	server  *dns.Server
	started chan struct{}
	served  chan error
	// ended is set once the result of served has been received.
	ended bool
}

func (t *transport) start() {
	t.started = make(chan struct{})
	t.served = make(chan error, 1)
	t.server.NotifyStartedFunc = func() { close(t.started) }
	go func() { t.served <- t.server.ActivateAndServe() }()
}

func (t *transport) failure(err error) error {
	return fmt.Errorf("xip: serving DNS over %s on %s: %w", t.name, t.address, err)
}

func (t *transport) stoppedByItself(err error) error {
	if err == nil {
		return fmt.Errorf("xip: the DNS read loop over %s on %s stopped without being shut down", t.name, t.address)
	}
	return t.failure(err)
}

// shutdown stops every transport whose read loop has not ended, waits for the loops to return and joins the errors they return.
func (xip *Xip) shutdown(ctx context.Context, transports []*transport) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, t := range transports {
		if t.ended {
			continue
		}
		wg.Go(func() {
			if err := t.server.ShutdownContext(shutdownCtx); err != nil {
				xip.logger.Warn().Err(err).Str("transport", t.name).Msg("DNS server did not shut down cleanly")
			}
		})
	}
	wg.Wait()

	// Waiting for the loops keeps the promise that no handler runs after Serve returns. Every network read and write a handler can block on is bounded by now: ShutdownContext has closed the UDP socket, which ends a handler blocked on its reply, every TCP connection has a read deadline in the past, and every TCP write has a deadline of its own. The wait itself has no timeout, since a handler can still be busy writing a log line; it only happens during a shutdown, which the supervisor's kill timeout or a second signal ends if it hangs.
	var errs []error
	for _, t := range transports {
		if t.ended {
			continue
		}
		if err := <-t.served; err != nil {
			errs = append(errs, t.failure(err))
		}
		t.ended = true
	}
	return errors.Join(errs...)
}

// boundedListener caps the open TCP connections and gives every write on them a deadline, so that a client that stops reading cannot hold a handler, and with it the shutdown, forever. A connection beyond the cap waits in the kernel's accept queue.
// It also reports on failed an accept error that ends the library's accept loop, the moment it happens: the library only returns that error once every open connection has finished, which can take minutes.
type boundedListener struct {
	net.Listener
	slots     chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	failed    chan error
}

func newBoundedListener(listener net.Listener, connections int) *boundedListener {
	return &boundedListener{
		Listener: listener,
		slots:    make(chan struct{}, connections),
		closed:   make(chan struct{}),
		failed:   make(chan error, 1),
	}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		// The library's accept loop retries after a temporary error and returns on any other, with the same test.
		if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() {
			select {
			case l.failed <- err:
			default:
			}
		}
		return nil, err
	}
	return &boundedConn{Conn: conn, release: func() { <-l.slots }, writeTimeout: tcpWriteTimeout}, nil
}

func (l *boundedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// boundedConn holds one of the listener's slots until it is closed.
type boundedConn struct {
	net.Conn
	release      func()
	releaseOnce  sync.Once
	writeTimeout time.Duration
}

func (c *boundedConn) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(b)
	if err != nil {
		// Part of the message may be on the stream already, so nothing written after it could be framed; closing also ends the library's loop on this connection at its next read.
		c.Close()
	}
	return n, err
}

func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}
