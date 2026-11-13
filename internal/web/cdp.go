package web

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// cdpClient speaks the Chrome DevTools Protocol over the WebSocket above.
//
// CDP is JSON-RPC-ish: requests carry an id and get a reply with the same id;
// events carry a method name and no id. The client keeps one reader goroutine and
// fans events out to handlers in their own goroutines (a handler that calls send()
// must not block the reader, or nothing would ever get a reply).
type cdpClient struct {
	ws *wsConn

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan cdpReply
	closed  bool

	hmu      sync.RWMutex
	handlers map[string][]cdpHandler

	done chan struct{}
	err  error
}

type cdpReply struct {
	Result json.RawMessage `json:"result"`
	Error  *cdpError       `json:"error"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *cdpError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message)
}

// cdpHandler receives one event. sessionID is set for flat-mode child sessions.
type cdpHandler func(sessionID string, params json.RawMessage)

type cdpEnvelope struct {
	ID        *int64          `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

// dialCDP opens the control channel.
func dialCDP(ctx context.Context, wsURL string) (*cdpClient, error) {
	ws, err := dialWS(ctx, wsURL)
	if err != nil {
		return nil, err
	}
	c := &cdpClient{
		ws:       ws,
		pending:  map[int64]chan cdpReply{},
		handlers: map[string][]cdpHandler{},
		done:     make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

func (c *cdpClient) readLoop() {
	defer close(c.done)
	for {
		_, payload, err := c.ws.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			return
		}
		var env cdpEnvelope
		if err := json.Unmarshal(payload, &env); err != nil {
			continue // a malformed frame must not kill the control channel
		}
		if env.ID != nil {
			c.mu.Lock()
			ch := c.pending[*env.ID]
			delete(c.pending, *env.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- cdpReply{Result: env.Result, Error: env.Error}
			}
			continue
		}
		if env.Method == "" {
			continue
		}
		c.hmu.RLock()
		handlers := c.handlers[env.Method]
		c.hmu.RUnlock()
		for _, h := range handlers {
			handler, sid, params := h, env.SessionID, env.Params
			go handler(sid, params)
		}
	}
}

// On registers an event handler.
func (c *cdpClient) On(method string, h cdpHandler) {
	c.hmu.Lock()
	defer c.hmu.Unlock()
	c.handlers[method] = append(c.handlers[method], h)
}

// Send performs one command and waits for its reply.
func (c *cdpClient) Send(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errWSClosed
	}
	c.nextID++
	id := c.nextID
	ch := make(chan cdpReply, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if err := c.ws.WriteText(raw); err != nil {
		return nil, err
	}

	select {
	case reply := <-ch:
		if reply.Error != nil {
			return nil, reply.Error
		}
		return reply.Result, nil
	case <-c.done:
		return nil, fmt.Errorf("web/cdp: control channel closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close shuts the control channel down.
func (c *cdpClient) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.ws.Close()
}

// waitFor blocks until an event matching method arrives or the timeout expires.
// It is used for Page.loadEventFired-style waits.
func (c *cdpClient) waitFor(ctx context.Context, method string, timeout time.Duration) bool {
	ch := make(chan struct{}, 1)
	c.On(method, func(string, json.RawMessage) {
		select {
		case ch <- struct{}{}:
		default:
		}
	})
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	case <-c.done:
		return false
	}
}
