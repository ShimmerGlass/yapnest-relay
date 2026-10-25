package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	nsComponent = "jabber:component:accept"
	nsStreams   = "http://etherx.jabber.org/streams"
)

// A stanza as it arrives, its payload left as XML for the handler.
type stanza struct {
	XMLName xml.Name
	From    string `xml:"from,attr"`
	To      string `xml:"to,attr"`
	ID      string `xml:"id,attr"`
	Type    string `xml:"type,attr"`
	Inner   []byte `xml:",innerxml"`
}

// component is the relay's connection to an XMPP server as an external component (XEP-0114): the server routes
// everything addressed to the domain here, including what other servers send it over s2s.
type component struct {
	domain  string
	server  string // host:port of the server's component listener
	secret  string
	handle  func(stanza)
	metrics *metrics // may be nil

	mu   sync.Mutex
	conn net.Conn
}

// run keeps the component connected until ctx ends, reconnecting with a growing delay.
func (c *component) run(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			delay = time.Second
		}
		slog.Warn("disconnected", "server", c.server, "err", err, "retry_in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}

func (c *component) session(ctx context.Context) error {
	established := false
	defer func() {
		if !established && ctx.Err() == nil {
			c.metrics.connect("error")
		}
	}()
	// A dead server is noticed in about a minute: by the keepalive probes while the connection is idle, and by the
	// user timeout once a write goes unacknowledged, since TCP sends no probes then.
	keepAlive := net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: keepAlive, Control: userTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	if _, err := fmt.Fprintf(conn, "<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' to='%s'>", nsComponent, nsStreams, escape(c.domain)); err != nil {
		return err
	}
	dec := xml.NewDecoder(conn)
	header, err := nextElement(dec)
	if err != nil {
		return err
	}
	if header.Name.Local != "stream" {
		return fmt.Errorf("expected a stream, got <%s>", header.Name.Local)
	}
	var id string
	for _, a := range header.Attr {
		if a.Name.Local == "id" {
			id = a.Value
		}
	}
	sum := sha1.Sum([]byte(id + c.secret))
	if _, err := fmt.Fprintf(conn, "<handshake>%s</handshake>", hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	reply, err := nextElement(dec)
	if err != nil {
		return err
	}
	if reply.Name.Local != "handshake" {
		return streamError(dec, reply)
	}
	if err := dec.Skip(); err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	established = true
	c.metrics.connect("ok")
	c.metrics.setConnected(true)
	defer func() {
		c.metrics.setConnected(false)
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()
	slog.Info("connected", "server", c.server, "domain", c.domain)
	go c.keepalive(conn, done)

	for {
		start, err := nextElement(dec)
		if err != nil {
			return err
		}
		if start.Name.Space == nsStreams && start.Name.Local == "error" {
			return streamError(dec, start)
		}
		var st stanza
		if err := dec.DecodeElement(&st, &start); err != nil {
			return err
		}
		go c.handle(st)
	}
}

// keepalive sends whitespace, which servers allow between stanzas, so idle connections aren't dropped. A send
// that fails closes conn, which ends the read loop so the component reconnects. Servers don't answer whitespace,
// so a connection that went silent is left to TCP's keepalive.
func (c *component) keepalive(conn net.Conn, done <-chan struct{}) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if err := c.send(" "); err != nil {
				conn.Close()
				return
			}
		}
	}
}

func (c *component) send(xml string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return errors.New("not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := io.WriteString(c.conn, xml)
	return err
}

// nextElement returns the next start tag, or an error at the end of the stream.
func nextElement(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			return xml.StartElement{}, io.EOF
		}
	}
}

func streamError(dec *xml.Decoder, start xml.StartElement) error {
	var body struct {
		Inner []byte `xml:",innerxml"`
	}
	_ = dec.DecodeElement(&body, &start)
	return fmt.Errorf("stream error: <%s>%s", start.Name.Local, strings.TrimSpace(string(body.Inner)))
}

func escape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
