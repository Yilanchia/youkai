package discipline

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// scopedDialer is the second half of the SSRF guard.
//
// The URL-level check cannot see what a hostname resolves to. Control() runs
// AFTER resolution and BEFORE connect, so it sees the real address - which is
// what stops a name from resolving into the private network (or rebinding to it)
// after the scope said yes.
type scopedDialer struct {
	scope   *Scope
	timeout time.Duration
	dialer  *net.Dialer
}

func newScopedDialer(scope *Scope, timeout time.Duration) *scopedDialer {
	d := &scopedDialer{scope: scope, timeout: timeout}
	d.dialer = &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   d.control,
	}
	return d
}

// DialContext dials with the scope applied to the resolved address.
func (d *scopedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

// control rejects connections to addresses the passport does not cover.
func (d *scopedDialer) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrOutOfScope, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: resolved address %q is not an IP", ErrOutOfScope, host)
	}
	if !isPrivateIP(ip) {
		return nil // public address; the URL check already approved the host
	}
	// Private space: the passport must opt in AND explicitly cover this literal
	// address. Otherwise a public hostname that resolves to 10.x would be a way
	// in.
	if !d.scope.AllowPrivate {
		return fmt.Errorf("%w: %s", ErrPrivateTarget, ip)
	}
	literal := "http://" + net.JoinHostPort(ip.String(), "80") + "/"
	if dec, err := d.scope.Check(literal); err != nil {
		_ = dec
		return fmt.Errorf("%w: resolved to private %s which the include list does not name", ErrPrivateTarget, ip)
	}
	return nil
}
