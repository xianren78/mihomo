package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

const NextProtoDQ = "doq"
const (
	// QUICCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	QUICCodeNoError = quic.ApplicationErrorCode(0)
	// QUICCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	QUICCodeInternalError    = quic.ApplicationErrorCode(1)
	QUICCodeProtocolError    = quic.ApplicationErrorCode(2)
	QUICCodeRequestCancelled = quic.StreamErrorCode(3)
	// QUICKeepAlivePeriod is the value that we pass to *quic.Config and that
	// controls the period with with keep-alive frames are being sent to the
	// connection. We set it to 20s as it would be in the quic-go@v0.27.1 with
	// KeepAlive field set to true This value is specified in
	// https://pkg.go.dev/github.com/metacubex/quic-go/internal/protocol#MaxKeepAliveInterval.
	//
	// TODO(ameshkov):  Consider making it configurable.
	QUICKeepAlivePeriod = time.Second * 20
	DefaultTimeout      = time.Second * 5
)

var (
	errDoQReset    = errors.New("DoQ connection reset during dialing")
	errDoQProtocol = errors.New("DoQ protocol error")
)

// doqDialCall is shared by queries waiting for the same handshake. All fields
// except done are protected by connMu; err is immutable after done is closed.
type doqDialCall struct {
	done      chan struct{}
	cancel    context.CancelFunc
	abandoned bool
	err       error
}

// dnsOverQUIC is a struct that implements the Upstream interface for the
// DNS-over-QUIC protocol (spec: https://www.rfc-editor.org/rfc/rfc9250.html).
type dnsOverQUIC struct {
	// quicConfig is the QUIC configuration that is used for establishing
	// connections to the upstream.  This configuration includes the TokenStore
	// that needs to be stored for the lifetime of dnsOverQUIC since we can
	// re-create the connection.
	quicConfig      *quic.Config
	quicConfigGuard sync.Mutex

	// conn is the current active QUIC connection.  It can be closed and
	// re-opened when needed.
	conn    *quic.Conn
	connMu  sync.Mutex
	dialing *doqDialCall
	closed  bool

	addr           string
	dialer         *dnsDialer
	skipCertVerify bool
	nameCertVerify string
}

// type check
var _ dnsClient = (*dnsOverQUIC)(nil)

// newDoQ returns the DNS-over-QUIC Upstream.
func newDoQ(addr string, resolver resolver.Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverQUIC {
	doq := &dnsOverQUIC{
		addr:   addr,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		},
	}

	if params["skip-cert-verify"] == "true" {
		doq.skipCertVerify = true
	}
	doq.nameCertVerify = params["name-cert-verify"]

	runtime.SetFinalizer(doq, (*dnsOverQUIC).Close)
	return doq
}

// Address implements the Upstream interface for *dnsOverQUIC.
func (doq *dnsOverQUIC) Address() string { return doq.addr }

func (doq *dnsOverQUIC) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// Keep the finalizer from closing a connection while a query is using it.
	defer runtime.KeepAlive(doq)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	m = m.Copy()
	id := m.Id
	m.Id = 0
	defer func() {
		if msg != nil {
			msg.Id = id
		}
	}()

	// Retry only connection errors known to be recoverable, at most twice.
	// Each attempt retains its connection identity, so a late error can never
	// close a replacement installed by another query.
	for attempt := 0; ; attempt++ {
		conn, connErr := doq.getConnection(ctx)
		if connErr != nil {
			return nil, connErr
		}
		msg, err = doq.exchangeQUIC(ctx, conn, m)
		if err == nil {
			return msg, nil
		}
		retry := isQUICRetryError(err)
		if retry || conn.Context().Err() != nil || errors.Is(err, errDoQProtocol) {
			doq.closeConnWithError(conn, err)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retry || attempt >= 2 {
			return nil, err
		}
		log.Debugln("re-creating the QUIC connection and retrying due to %v", err)
	}
}

// Close permanently closes this client. ResetConnection permits later dialing.
func (doq *dnsOverQUIC) Close() error {
	doq.connMu.Lock()
	runtime.SetFinalizer(doq, nil)
	doq.closed = true
	conn := doq.conn
	doq.conn = nil
	if doq.dialing != nil {
		doq.dialing.abandoned = true
		doq.dialing.cancel()
	}
	doq.connMu.Unlock()
	if conn != nil {
		return conn.CloseWithError(QUICCodeNoError, "")
	}
	return nil
}

func (doq *dnsOverQUIC) ResetConnection() {
	doq.connMu.Lock()
	conn := doq.conn
	doq.conn = nil
	if doq.dialing != nil {
		doq.dialing.abandoned = true
		doq.dialing.cancel()
	}
	doq.connMu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(QUICCodeNoError, "")
	}
}

// exchangeQUIC exchanges one message on the supplied shared connection.
func (doq *dnsOverQUIC) exchangeQUIC(ctx context.Context, conn *quic.Conn, msg *D.Msg) (resp *D.Msg, err error) {
	// All DNS messages (queries and responses) sent over DoQ connections MUST
	// be encoded as a 2-octet length field followed by the message content as
	// specified in [RFC1035].
	// Note: we do not support receiving multiple responses over a single stream.
	buf := pool.Get(2 + MaxMsgSize)
	defer pool.Put(buf)
	b, err := msg.PackBuffer(buf[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message for DoQ: %w", err)
	}
	if len(b) > MaxMsgSize {
		return nil, fmt.Errorf("DNS message is too large: %d > %d", len(b), MaxMsgSize)
	}
	binary.BigEndian.PutUint16(buf, uint16(len(b)))

	// A query waiting for stream credit must not reconnect on cancellation.
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	cancelDone := make(chan struct{})
	stop := contextutils.AfterFunc(ctx, func() {
		stream.CancelRead(QUICCodeRequestCancelled)
		stream.CancelWrite(QUICCodeRequestCancelled)
		close(cancelDone)
	})
	defer func() {
		// AfterFunc's stop does not wait for a callback already in progress.
		if !stop() {
			<-cancelDone
		}
		if ctx.Err() != nil {
			resp, err = nil, ctx.Err()
		}
		if err != nil {
			code := quic.StreamErrorCode(QUICCodeInternalError)
			if ctx.Err() != nil {
				code = QUICCodeRequestCancelled
			}
			stream.CancelRead(code)
			stream.CancelWrite(code)
		}
	}()

	_, err = stream.Write(buf[:2+len(b)])
	if err != nil {
		return nil, fmt.Errorf("failed to write to a QUIC stream: %w", err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream. Note, that stream.Close() closes the
	// write-direction of the stream, but does not prevent reading from it.
	if err = stream.Close(); err != nil {
		return nil, fmt.Errorf("closing QUIC stream write side: %w", err)
	}

	// -- reading the response ---
	var respLen uint16
	err = binary.Read(stream, binary.BigEndian, &respLen)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: truncated response length from %s", errDoQProtocol, doq.Address())
		}
		return nil, fmt.Errorf("reading response length from %s: %w", doq.Address(), err)
	}
	if respLen == 0 {
		return nil, fmt.Errorf("%w: empty response from %s", errDoQProtocol, doq.Address())
	}
	if respLen > MaxMsgSize {
		return nil, fmt.Errorf("%w: response is too large: %d > %d", errDoQProtocol, respLen, MaxMsgSize)
	}

	_, err = io.ReadFull(stream, buf[:respLen])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: truncated response from %s", errDoQProtocol, doq.Address())
		}
		return nil, fmt.Errorf("reading response from %s: %w", doq.Address(), err)
	}

	resp = new(D.Msg)
	err = resp.Unpack(buf[:respLen])
	if err != nil {
		return nil, fmt.Errorf("%w: unpacking response from %s: %v", errDoQProtocol, doq.Address(), err)
	}

	if resp.Id != 0 {
		return nil, fmt.Errorf("%w: nonzero response ID from %s", errDoQProtocol, doq.Address())
	}
	// Consume the peer's FIN. Reading exactly the DNS payload is not enough
	// to finish the receive side when the FIN arrives in a later packet.
	var extra [1]byte
	n, readErr := io.ReadFull(stream, extra[:])
	if n != 0 {
		return nil, fmt.Errorf("%w: unexpected data after response from %s", errDoQProtocol, doq.Address())
	}
	if readErr != io.EOF {
		return nil, fmt.Errorf("reading QUIC stream FIN from %s: %w", doq.Address(), readErr)
	}

	return resp, nil
}

// getConnection reuses a live connection or joins the single in-flight dial.
// Network I/O never holds connMu, and waiting queries honor their own context.
func (doq *dnsOverQUIC) getConnection(ctx context.Context) (*quic.Conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		doq.connMu.Lock()
		if doq.closed {
			doq.connMu.Unlock()
			return nil, net.ErrClosed
		}
		if conn := doq.conn; conn != nil {
			if conn.Context().Err() == nil {
				doq.connMu.Unlock()
				return conn, nil
			}
			// A terminated quic.Conn releases its single-use transport itself.
			doq.conn = nil
		}
		if call := doq.dialing; call != nil {
			doq.connMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-call.done:
			}
			// One caller's cancelled handshake must not cancel other queries.
			if call.err != nil && !errors.Is(call.err, errDoQReset) &&
				!errors.Is(call.err, context.Canceled) && !errors.Is(call.err, context.DeadlineExceeded) {
				return nil, call.err
			}
			continue
		}

		dialCtx, cancel := context.WithCancel(ctx)
		call := &doqDialCall{done: make(chan struct{}), cancel: cancel}
		doq.dialing = call
		doq.connMu.Unlock()

		conn, err := doq.openConnection(dialCtx)
		cancel()

		doq.connMu.Lock()
		switch {
		case doq.closed:
			err = net.ErrClosed
		case call.abandoned:
			err = errDoQReset
		case ctx.Err() != nil:
			err = ctx.Err()
		}
		if err == nil {
			doq.conn = conn
		} else if conn != nil {
			// A reset/close may race with a successful handshake. Never publish
			// or leak that connection. Close outside the state lock.
			doq.connMu.Unlock()
			_ = conn.CloseWithError(QUICCodeNoError, "")
			doq.connMu.Lock()
		}
		call.err = err
		doq.dialing = nil
		close(call.done)
		doq.connMu.Unlock()

		if errors.Is(err, errDoQReset) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (doq *dnsOverQUIC) getQUICConfig() (c *quic.Config) {
	doq.quicConfigGuard.Lock()
	defer doq.quicConfigGuard.Unlock()

	return doq.quicConfig
}

// resetQUICConfig re-creates the tokens store as we may need to use a new one
// if we failed to connect.
func (doq *dnsOverQUIC) resetQUICConfig() {
	doq.quicConfigGuard.Lock()
	defer doq.quicConfigGuard.Unlock()

	doq.quicConfig = doq.quicConfig.Clone()
	doq.quicConfig.TokenStore = newQUICTokenStore()
}

// openConnection opens a new QUIC connection.
func (doq *dnsOverQUIC) openConnection(ctx context.Context) (quicConn *quic.Conn, err error) {
	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses).
	rawConn, err := doq.dialer.DialContext(ctx, "udp", doq.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to open a QUIC connection: %w", err)
	}
	addr := rawConn.RemoteAddr().String()
	// It's never actually used
	_ = rawConn.Close()

	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid QUIC port: %q", port)
	}
	// ResolveUDPAddr also preserves the zone of an IPv6 link-local address.
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, strconv.Itoa(p)))
	if err != nil {
		return nil, err
	}
	packetConn, err := doq.dialer.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(doq.addr)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: doq.skipCertVerify,
			NextProtos: []string{
				NextProtoDQ,
			},
			SessionTicketsDisabled: false,
		},
		NameCertVerify: doq.nameCertVerify,
	})
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}

	transport := quic.Transport{Conn: packetConn}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	quicConn, err = transport.Dial(ctx, udpAddr, tlsConfig, doq.getQUICConfig())
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, fmt.Errorf("opening quic connection to %s: %w", doq.addr, err)
	}

	return quicConn, nil
}

// closeConnWithError retires only the failed connection. Another query may
// already have installed a replacement by the time this error is processed.
func (doq *dnsOverQUIC) closeConnWithError(conn *quic.Conn, err error) {
	doq.connMu.Lock()
	if doq.conn == conn {
		doq.conn = nil
		if errors.Is(err, quic.Err0RTTRejected) {
			doq.resetQUICConfig()
		}
	}
	doq.connMu.Unlock()

	code := QUICCodeInternalError
	if err == nil {
		code = QUICCodeNoError
	} else if errors.Is(err, errDoQProtocol) {
		code = QUICCodeProtocolError
	}
	if closeErr := conn.CloseWithError(code, ""); closeErr != nil {
		log.Errorln("failed to close the QUIC conn: %v", closeErr)
	}
}

// newQUICTokenStore caches address-validation tokens. Transport.Dial does not
// send 0-RTT application data; that would require DialEarly and session caching.
func newQUICTokenStore() (s quic.TokenStore) {
	// You can read more on address validation here:
	// https://datatracker.ietf.org/doc/html/rfc9000#section-8.1
	// Setting maxOrigins to 1 and tokensPerOrigin to 10 assuming that this is
	// more than enough for the way we use it (one connection per upstream).
	return quic.NewLRUTokenStore(1, 10)
}

// isQUICRetryError checks the error and determines whether it may signal that
// we should re-create the QUIC connection.  This requirement is caused by
// quic-go issues, see the comments inside this function.
// TODO(ameshkov): re-test when updating quic-go.
func isQUICRetryError(err error) (ok bool) {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		// This error is often returned when the server has been restarted,
		// and we try to use the same connection on the client-side. It seems,
		// that the old connections aren't closed immediately on the server-side
		// and that's why one can run into this.
		// In addition to that, quic-go HTTP3 client implementation does not
		// clean up dead connections (this one is specific to DoH3 upstream):
		// https://github.com/metacubex/quic-go/issues/765
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		// This error means that the connection was closed due to being idle.
		// In this case we should forcibly re-create the QUIC connection.
		// Reproducing is rather simple, stop the server and wait for 30 seconds
		// then try to send another request via the same upstream.
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		// A stateless reset is sent when a server receives a QUIC packet that
		// it doesn't know how to decrypt.  For instance, it may happen when
		// the server was recently rebooted.  We should reconnect and try again
		// in this case.
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		// A transport error with the NO_ERROR error code could be sent by the
		// server when it considers that it's time to close the connection.
		// For example, Google DNS eventually closes an active connection with
		// the NO_ERROR code and "Connection max age expired" message:
		// https://github.com/AdguardTeam/dnsproxy/issues/283
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// This error happens when we try to establish a 0-RTT connection with
		// a token the server is no more aware of.  This can be reproduced by
		// restarting the QUIC server (it will clear its tokens cache).  The
		// next connection attempt will return this error until the client's
		// tokens cache is purged.
		return true
	}

	return false
}
