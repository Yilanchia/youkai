package web

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A minimal RFC 6455 WebSocket client, hand-written for one reason: the CDP
// control channel is the only way to drive a browser, and pulling a WebSocket
// library into a security tool to talk to 127.0.0.1 is a dependency you cannot
// justify. The scope is exactly what CDP needs: text/binary frames, fragmentation,
// ping/pong, and a hard message cap.
//
// This is NOT a general WebSocket client and it is NOT an egress path: dialWS
// refuses any endpoint whose host is not loopback, and the browser's own target
// traffic is gated per request by discipline.Guard (see browser.go).

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA

	// maxWSMessage caps a single message. Screenshots arrive base64 inside a JSON
	// text frame, so the cap is generous but finite.
	maxWSMessage = 64 << 20
)

var errWSClosed = errors.New("web/cdp: websocket closed")

type wsConn struct {
	conn   net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed bool
}

// dialWS connects to a ws:// URL on loopback and completes the upgrade.
func dialWS(ctx context.Context, rawURL string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("web/cdp: parse endpoint: %w", err)
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("web/cdp: endpoint scheme %q is not ws", u.Scheme)
	}
	host := u.Hostname()
	if !isLoopbackHost(host) {
		return nil, fmt.Errorf("web/cdp: refusing to connect to non-loopback CDP endpoint %q", host)
	}
	port := u.Port()
	if port == "" {
		return nil, fmt.Errorf("web/cdp: endpoint has no port")
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("web/cdp: dial %s: %w", u.Host, err)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		_ = conn.Close()
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + keyB64 + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"User-Agent: youkai/0.3\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("web/cdp: write handshake: %w", err)
	}

	br := bufio.NewReaderSize(conn, 64<<10)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("web/cdp: read handshake: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		_ = conn.Close()
		return nil, fmt.Errorf("web/cdp: handshake refused: %s", strings.TrimSpace(statusLine))
	}
	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("web/cdp: read handshake headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	want := wsAccept(keyB64)
	if got := headers["sec-websocket-accept"]; got != want {
		_ = conn.Close()
		return nil, fmt.Errorf("web/cdp: handshake accept mismatch")
	}

	_ = conn.SetDeadline(time.Time{})
	return &wsConn{conn: conn, br: br}, nil
}

func wsAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// WriteText sends one masked text frame.
func (c *wsConn) WriteText(payload []byte) error {
	return c.writeFrame(opText, payload)
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return errWSClosed
	}

	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode) // FIN + opcode
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126, byte(n>>8), byte(n))
	default:
		header = append(header, 0x80|127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(n))
		header = append(header, lenBuf[:]...)
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	header = append(header, mask...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.conn.Write(masked); err != nil {
			return err
		}
	}
	return nil
}

// ReadMessage returns the next complete message (fragments reassembled, control
// frames handled). It returns io.EOF after a close frame.
func (c *wsConn) ReadMessage() (byte, []byte, error) {
	var messageOp byte
	var payload []byte
	for {
		fin, opcode, frame, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case opPing:
			// Answer without blocking the reader: the peer may be mid-write on an
			// unbuffered connection, and a reader that blocks on a control write is
			// a deadlock waiting to happen.
			payload := append([]byte(nil), frame...)
			go func() { _ = c.writeFrame(opPong, payload) }()
			continue
		case opPong:
			continue
		case opClose:
			go func() { _ = c.writeFrame(opClose, nil) }()
			return 0, nil, io.EOF
		case opContinuation:
			if messageOp == 0 {
				return 0, nil, fmt.Errorf("web/cdp: continuation frame without a start")
			}
		case opText, opBinary:
			if messageOp != 0 {
				return 0, nil, fmt.Errorf("web/cdp: new data frame inside a fragmented message")
			}
			messageOp = opcode
		default:
			return 0, nil, fmt.Errorf("web/cdp: unsupported opcode 0x%x", opcode)
		}
		if len(payload)+len(frame) > maxWSMessage {
			return 0, nil, fmt.Errorf("web/cdp: message exceeds %d bytes", maxWSMessage)
		}
		payload = append(payload, frame...)
		if fin {
			return messageOp, payload, nil
		}
	}
}

func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var head [2]byte
	if _, err = io.ReadFull(c.br, head[:]); err != nil {
		return false, 0, nil, err
	}
	fin = head[0]&0x80 != 0
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxWSMessage {
		return false, 0, nil, fmt.Errorf("web/cdp: frame of %d bytes exceeds the cap", length)
	}
	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, maskKey[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(c.br, payload); err != nil {
			return false, 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// Close shuts the socket down.
func (c *wsConn) Close() error {
	c.wmu.Lock()
	if c.closed {
		c.wmu.Unlock()
		return nil
	}
	c.closed = true
	c.wmu.Unlock()
	return c.conn.Close()
}
