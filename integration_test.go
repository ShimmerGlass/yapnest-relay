//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIntegration runs the relay against real XMPP servers in Docker, through the whole flow: a user finds the
// relay, registers a device, enables push, goes away; a message for them makes their server publish to the relay,
// which pushes to a fake APNs. Run it with: go test -tags integration -run Integration -v ./...
func TestIntegration(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker isn't installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker isn't running")
	}
	servers := []struct {
		name, image, config, target string
		register                    []string // the command that registers user, host, password, as its arguments
	}{
		{"prosody", "prosodyim/prosody:13.0", "prosody.cfg.lua", "/etc/prosody/prosody.cfg.lua",
			[]string{"prosodyctl", "register"}},
		{"ejabberd", "ghcr.io/processone/ejabberd:latest", "ejabberd.yml", "/opt/ejabberd/conf/ejabberd.yml",
			[]string{"ejabberdctl", "register"}},
	}
	for _, s := range servers {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			config, err := filepath.Abs(filepath.Join("testdata", "integration", s.config))
			if err != nil {
				t.Fatal(err)
			}
			c2s, comp := integrationStart(t, s.name, s.image, config, s.target, s.register)
			integrationFlow(t, c2s, comp)
		})
	}
}

func integrationDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// integrationStart runs the server's container and returns the host addresses of its c2s and component ports,
// once it accepts connections and has registered alice and bob.
func integrationStart(t *testing.T, name, image, config, target string, register []string) (c2s, comp string) {
	t.Helper()
	container := fmt.Sprintf("yapnest-relay-it-%s-%d", name, time.Now().UnixNano())
	integrationDocker(t, "run", "-d", "--name", container,
		"-v", config+":"+target+":ro",
		"-p", "127.0.0.1::5222", "-p", "127.0.0.1::5347", image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	ok := false
	defer func() {
		if !ok {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
			t.Logf("%s logs:\n%s", name, logs)
		}
	}()

	addr := func(port string) string {
		// docker port prints one "ip:port" per line, IPv4 first.
		out := integrationDocker(t, "port", container, port+"/tcp")
		line, _, _ := strings.Cut(out, "\n")
		return strings.TrimSpace(line)
	}
	c2s, comp = addr("5222"), addr("5347")

	deadline := time.Now().Add(60 * time.Second)
	var last string
	for {
		if time.Now().After(deadline) {
			t.Fatalf("%s wasn't ready in 60 s: %s", name, last)
		}
		time.Sleep(time.Second)
		conn, err := net.DialTimeout("tcp", c2s, time.Second)
		if err != nil {
			last = err.Error()
			continue
		}
		conn.Close()
		good := true
		for _, user := range []string{"alice", "bob"} {
			args := append([]string{"exec", container}, register...)
			args = append(args, user, "localhost", "password")
			if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil &&
				!strings.Contains(string(out), "already") {
				last = fmt.Sprintf("register %s: %v: %s", user, err, out)
				good = false
				break
			}
		}
		if good {
			break
		}
	}
	ok = true
	return c2s, comp
}

func integrationFlow(t *testing.T, c2sAddr, compAddr string) {
	// A fake APNs.
	var mu sync.Mutex
	var paths []string
	apnsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
	}))
	apnsSrv.EnableHTTP2 = true
	apnsSrv.StartTLS()
	t.Cleanup(apnsSrv.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := newSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}

	// The relay, wired as main does, with what it sends and what it is asked recorded.
	c := &component{domain: "push.localhost", server: compAddr, secret: "relay"}
	r := &relay{
		domain: "push.localhost",
		nodes:  nodes,
		apns: &apns{
			key: key, keyID: "KEYID", teamID: "TEAMID", topic: "fr.yapnest.app",
			production: apnsSrv.URL, sandbox: apnsSrv.URL, client: apnsSrv.Client(),
		},
		window: pushWindow,
	}
	var sent, publishIDs []string
	r.send = func(s string) error {
		mu.Lock()
		sent = append(sent, s)
		mu.Unlock()
		return c.send(s)
	}
	c.handle = func(st stanza) {
		if bytes.Contains(st.Inner, []byte("<publish")) {
			mu.Lock()
			publishIDs = append(publishIDs, st.ID)
			mu.Unlock()
		}
		r.handle(st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	// The server takes a moment to see the component: wait until it answers a disco.
	alice := integrationLogin(t, c2sAddr, "alice")
	var info string
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		reply := alice.iq("get", "push.localhost", `<query xmlns='http://jabber.org/protocol/disco#info'/>`)
		if reply.Type == "result" {
			info = reply.Inner
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("push.localhost never answered disco#info: %s", alice.received())
		}
	}
	if !strings.Contains(info, "urn:xmpp:push:0") {
		t.Fatalf("disco#info lacks urn:xmpp:push:0: %s", info)
	}

	// The command's first stage: a form with a token field.
	reply := alice.iq("set", "push.localhost",
		`<command xmlns='http://jabber.org/protocol/commands' node='register-push-apns' action='execute'/>`)
	var staged integrationCommand
	reply.decodeCommand(t, &staged)
	if reply.Type != "result" || staged.Status != "executing" || staged.field("token") == nil {
		t.Fatalf("first stage = %s %s", reply.Type, reply.Inner)
	}

	// The whole command in one go.
	token := strings.Repeat("0123456789abcdef", 4)
	reply = alice.iq("set", "push.localhost", `<command xmlns='http://jabber.org/protocol/commands' node='register-push-apns' action='execute'>`+
		`<x xmlns='jabber:x:data' type='submit'>`+
		`<field var='token'><value>`+token+`</value></field>`+
		`<field var='environment'><value>production</value></field>`+
		`</x></command>`)
	var done2 integrationCommand
	reply.decodeCommand(t, &done2)
	var node string
	if f := done2.field("node"); f != nil && len(f.Values) > 0 {
		node = f.Values[0]
	}
	if reply.Type != "result" || done2.Status != "completed" || node == "" {
		t.Fatalf("registration = %s %s", reply.Type, reply.Inner)
	}

	reply = alice.iq("set", "", `<enable xmlns='urn:xmpp:push:0' jid='push.localhost' node='`+node+`'/>`)
	if reply.Type != "result" {
		t.Fatalf("enable = %s %s", reply.Type, reply.Inner)
	}
	alice.close()

	bob := integrationLogin(t, c2sAddr, "bob")
	defer bob.close()
	bob.write(`<message to='alice@localhost' type='chat'><body>hi</body></message>`)

	want := "POST /3/device/" + token
	var got []string
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		mu.Lock()
		got = append([]string(nil), paths...)
		mu.Unlock()
		if len(got) > 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(got) == 0 || got[0] != want {
		mu.Lock()
		out := fmt.Sprintf("%q", sent)
		mu.Unlock()
		t.Fatalf("APNs got %q, want %q\nrelay sent: %s\nbob received: %s", got, want, out, bob.received())
	}

	// The server's publish got a result, not an error.
	var publishReply string
	for deadline := time.Now().Add(5 * time.Second); publishReply == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		mu.Lock()
		for _, s := range sent {
			var out struct {
				Type string `xml:"type,attr"`
				ID   string `xml:"id,attr"`
			}
			if xml.Unmarshal([]byte(s), &out) != nil {
				continue
			}
			for _, id := range publishIDs {
				if out.ID == id {
					publishReply = out.Type
				}
			}
		}
		mu.Unlock()
	}
	if publishReply != "result" {
		mu.Lock()
		out := fmt.Sprintf("publishes %q, sent %q", publishIDs, sent)
		mu.Unlock()
		t.Fatalf("reply to the publish = %q, want result (%s)", publishReply, out)
	}
}

type integrationField struct {
	Var    string   `xml:"var,attr"`
	Values []string `xml:"value"`
}

// integrationCommand is the command element of a reply.
type integrationCommand struct {
	Status string `xml:"status,attr"`
	Form   struct {
		Fields []integrationField `xml:"field"`
	} `xml:"jabber:x:data x"`
}

func (c *integrationCommand) field(name string) *integrationField {
	for i := range c.Form.Fields {
		if c.Form.Fields[i].Var == name {
			return &c.Form.Fields[i]
		}
	}
	return nil
}

// integrationStanza is a received iq, message or presence.
type integrationStanza struct {
	XMLName xml.Name
	ID      string `xml:"id,attr"`
	Type    string `xml:"type,attr"`
	Inner   string `xml:",innerxml"`
}

func (s integrationStanza) decodeCommand(t *testing.T, out *integrationCommand) {
	t.Helper()
	if s.Type != "result" {
		return
	}
	if err := xml.Unmarshal([]byte(s.Inner), out); err != nil {
		t.Fatalf("command reply %s: %v", s.Inner, err)
	}
}

// integrationClient is a minimal c2s client: plaintext, SASL PLAIN, one resource.
type integrationClient struct {
	t    *testing.T
	conn net.Conn
	dec  *xml.Decoder
	log  []string
	n    int
}

func (c *integrationClient) write(s string) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatalf("write %s: %v\nreceived: %s", s, err, c.received())
	}
}

func (c *integrationClient) received() string { return strings.Join(c.log, "\n") }

// next reads the next top-level element, whatever it is.
func (c *integrationClient) next() (xml.StartElement, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		tok, err := c.dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start, nil
		}
	}
}

// expect reads elements until one named local arrives, and returns it decoded.
func (c *integrationClient) expect(local string) integrationStanza {
	c.t.Helper()
	for {
		start, err := c.next()
		if err != nil {
			c.t.Fatalf("waiting for <%s>: %v\nreceived: %s", local, err, c.received())
		}
		var st integrationStanza
		if start.Name.Local == "stream" {
			// A stream header has no end until the stream closes: there is nothing to decode.
			continue
		}
		if err := c.dec.DecodeElement(&st, &start); err != nil {
			c.t.Fatalf("waiting for <%s>: %v\nreceived: %s", local, err, c.received())
		}
		c.log = append(c.log, fmt.Sprintf("<%s id=%q type=%q>%s", st.XMLName.Local, st.ID, st.Type, st.Inner))
		if start.Name.Local == local || start.Name.Local == "failure" {
			return st
		}
	}
}

// iq sends an iq with payload and waits for the reply with its id.
func (c *integrationClient) iq(typ, to, payload string) integrationStanza {
	c.t.Helper()
	c.n++
	id := fmt.Sprintf("q%d", c.n)
	toAttr := ""
	if to != "" {
		toAttr = " to='" + to + "'"
	}
	c.write(fmt.Sprintf("<iq type='%s' id='%s'%s>%s</iq>", typ, id, toAttr, payload))
	for {
		st := c.expect("iq")
		if st.ID == id && (st.Type == "result" || st.Type == "error") {
			return st
		}
	}
}

func (c *integrationClient) openStream() {
	c.t.Helper()
	c.write("<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0'>")
	if start, err := c.next(); err != nil || start.Name.Local != "stream" {
		c.t.Fatalf("expected a stream header: %v %v", start.Name, err)
	}
	c.expect("features")
}

func integrationLogin(t *testing.T, addr, user string) *integrationClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &integrationClient{t: t, conn: conn, dec: xml.NewDecoder(conn)}
	c.openStream()
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00password"))
	c.write("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>" + plain + "</auth>")
	if st := c.expect("success"); st.XMLName.Local != "success" {
		t.Fatalf("sign-in as %s failed: %s", user, c.received())
	}
	c.openStream()
	reply := c.iq("set", "", "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>it</resource></bind>")
	if reply.Type != "result" {
		t.Fatalf("bind: %s", reply.Inner)
	}
	c.write("<presence/>")
	return c
}

// close ends the stream the way a client does, and waits for the server to hang up.
func (c *integrationClient) close() {
	c.write("</stream:stream>")
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, c.conn)
	c.conn.Close()
}
