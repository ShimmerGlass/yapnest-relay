package main

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	nsDiscoInfo  = "http://jabber.org/protocol/disco#info"
	nsDiscoItems = "http://jabber.org/protocol/disco#items"
	nsCommands   = "http://jabber.org/protocol/commands"
	nsPubsub     = "http://jabber.org/protocol/pubsub"
	nsData       = "jabber:x:data"
	nsPing       = "urn:xmpp:ping"
	nsPush       = "urn:xmpp:push:0"
	nsStanzas    = "urn:ietf:params:xml:ns:xmpp-stanzas"

	// The ad-hoc command (XEP-0050) the app runs to get a node for its device token.
	registerNode = "register-push-apns"
	registerName = "Register an iOS device"

	// The AGPL asks the relay to offer its source to whoever uses it over the network: disco#info names it.
	sourceURL = "https://github.com/ShimmerGlass/yapnest-relay"
)

type pusher interface {
	push(context.Context, registration) error
}

// relay is the XEP-0357 app server: devices register their APNs token and get a node back, then hand the node
// to their own server, which publishes to it whenever a message arrives while they're away.
type relay struct {
	domain string
	nodes  *sealer
	apns   pusher
	send   func(string) error
	// window is the shortest time between two pushes to a device; 0 for none.
	window time.Duration
	// metrics may be nil.
	metrics *metrics

	mu        sync.Mutex
	recent    map[string]*throttle // by node
	lastSweep time.Time            // when recent last dropped its idle entries
	draining  bool                 // drain has started: nothing waits for a window any more
	busy      int                  // the pushes schedule promised, at once or trailing, and not finished
	idle      chan struct{}        // closed when busy drops to 0, while drain waits for it
}

// Servers publish for more than messages (ejabberd's default pushes for presence and PEP events too), so
// publishes come in bursts. Each push wakes the app's extension, which catches up on everything: one push per
// window is enough, as long as the last publish of a burst still gets one.
const pushWindow = 10 * time.Second

type throttle struct {
	last  time.Time
	timer *time.Timer // non-nil while a trailing push is scheduled
}

// idle is whether the entry can go: no trailing push pending, and its last push older than the window.
func (t *throttle) idle(now time.Time, window time.Duration) bool {
	return t.timer == nil && now.Sub(t.last) > window
}

func (r *relay) handle(st stanza) {
	if st.XMLName.Local != "iq" || (st.Type != "get" && st.Type != "set") {
		return // messages, presence and replies need nothing
	}
	var payload struct {
		XMLName xml.Name
		Node    string `xml:"node,attr"`
	}
	if err := xml.Unmarshal(st.Inner, &payload); err != nil {
		r.reply(st, stanzaErr("modify", "bad-request"))
		return
	}
	switch {
	case st.Type == "get" && payload.XMLName.Space == nsDiscoInfo:
		r.discoInfo(st, payload.Node)
	case st.Type == "get" && payload.XMLName.Space == nsDiscoItems:
		q := &discoItems{XMLName: xml.Name{Space: nsDiscoItems, Local: "query"}, Node: payload.Node}
		if payload.Node == nsCommands {
			q.Items = []item{{JID: r.domain, Node: registerNode, Name: registerName}}
		}
		r.reply(st, q)
	case st.Type == "get" && payload.XMLName.Space == nsPing:
		r.reply(st, nil)
	case st.Type == "set" && payload.XMLName.Space == nsCommands && payload.Node == registerNode:
		r.register(st)
	case st.Type == "set" && payload.XMLName.Space == nsPubsub:
		r.publish(st)
	default:
		r.reply(st, stanzaErr("cancel", "service-unavailable"))
	}
}

func (r *relay) discoInfo(st stanza, node string) {
	switch node {
	case "":
		q := newDiscoInfo("", identity{Category: "pubsub", Type: "push", Name: "Yapnest push relay"},
			nsDiscoInfo, nsCommands, nsPush, nsPing)
		// Software information (XEP-0232), with where to get the source.
		q.Form = &dataForm{XMLName: xml.Name{Space: nsData, Local: "x"}, Type: "result", Fields: []formField{
			{Var: "FORM_TYPE", Type: "hidden", Values: []string{"urn:xmpp:dataforms:softwareinfo"}},
			{Var: "software", Values: []string{"yapnest-relay"}},
			{Var: "source", Values: []string{sourceURL}},
		}}
		r.reply(st, q)
	case registerNode:
		r.reply(st, newDiscoInfo(registerNode, identity{Category: "automation", Type: "command-node", Name: registerName},
			nsCommands, nsData))
	default:
		r.reply(st, stanzaErr("cancel", "item-not-found"))
	}
}

type item struct {
	JID  string `xml:"jid,attr"`
	Node string `xml:"node,attr"`
	Name string `xml:"name,attr"`
}

type discoItems struct {
	XMLName xml.Name
	Node    string `xml:"node,attr"`
	Items   []item `xml:"item"`
}

type identity struct {
	Category string `xml:"category,attr"`
	Type     string `xml:"type,attr"`
	Name     string `xml:"name,attr"`
}

type feature struct {
	Var string `xml:"var,attr"`
}

type discoInfo struct {
	XMLName  xml.Name
	Node     string    `xml:"node,attr,omitempty"`
	Identity identity  `xml:"identity"`
	Features []feature `xml:"feature"`
	Form     *dataForm `xml:"x"` // extended information (XEP-0128)
}

func newDiscoInfo(node string, id identity, features ...string) *discoInfo {
	q := &discoInfo{XMLName: xml.Name{Space: nsDiscoInfo, Local: "query"}, Node: node, Identity: id}
	for _, f := range features {
		q.Features = append(q.Features, feature{Var: f})
	}
	return q
}

// dataForm (XEP-0004) is both the form the relay sends and the one the app submits.
type dataForm struct {
	XMLName xml.Name
	Type    string      `xml:"type,attr"`
	Title   string      `xml:"title,omitempty"`
	Fields  []formField `xml:"field"`
}

type formField struct {
	Var      string       `xml:"var,attr"`
	Type     string       `xml:"type,attr,omitempty"`
	Label    string       `xml:"label,attr,omitempty"`
	Required *struct{}    `xml:"required"`
	Values   []string     `xml:"value"`
	Options  []formOption `xml:"option"`
}

type formOption struct {
	Value string `xml:"value"`
}

// command is the ad-hoc command (XEP-0050) element, as the relay answers it.
type command struct {
	XMLName   xml.Name
	Node      string    `xml:"node,attr"`
	SessionID string    `xml:"sessionid,attr"`
	Status    string    `xml:"status,attr"`
	Actions   *actions  `xml:"actions"`
	Form      *dataForm `xml:"x"`
}

type actions struct {
	Execute  string   `xml:"execute,attr"`
	Complete struct{} `xml:"complete"`
}

func (f *dataForm) value(name string) string {
	for _, field := range f.Fields {
		if field.Var == name && len(field.Values) > 0 {
			return strings.TrimSpace(field.Values[0])
		}
	}
	return ""
}

// register answers the command with a node for the device. Apps submit the form in one go; anything else gets the
// form to fill in, as the command's first stage.
func (r *relay) register(st stanza) {
	var cmd struct {
		Action    string    `xml:"action,attr"`
		SessionID string    `xml:"sessionid,attr"`
		Form      *dataForm `xml:"jabber:x:data x"`
	}
	if err := xml.Unmarshal(st.Inner, &cmd); err != nil {
		r.metrics.registration("unknown", "bad_form")
		r.reply(st, stanzaErr("modify", "bad-request"))
		return
	}
	answer := func(status string) *command {
		return &command{XMLName: xml.Name{Space: nsCommands, Local: "command"}, Node: registerNode,
			SessionID: cmp.Or(cmd.SessionID, st.ID), Status: status}
	}
	switch {
	case cmd.Action == "cancel":
		r.reply(st, answer("canceled"))
		return
	case cmd.Form == nil || cmd.Form.Type != "submit":
		c := answer("executing")
		c.Actions = &actions{Execute: "complete"}
		c.Form = &dataForm{XMLName: xml.Name{Space: nsData, Local: "x"}, Type: "form", Title: registerName, Fields: []formField{
			{Var: "token", Type: "text-single", Label: "APNs device token, in hex", Required: &struct{}{}},
			{Var: "environment", Type: "list-single", Label: "Environment", Values: []string{"production"},
				Options: []formOption{{"production"}, {"sandbox"}}},
		}}
		r.reply(st, c)
		return
	}

	// Only the two environments are labels; whatever else the form said is not.
	var label string
	switch cmd.Form.value("environment") {
	case "", "production":
		label = "production"
	case "sandbox":
		label = "sandbox"
	default:
		label = "unknown"
	}
	token, err := hex.DecodeString(cmd.Form.value("token"))
	reg := registration{Token: token, Sandbox: label == "sandbox", Owner: normalizeJID(st.From)}
	// Sealing refuses a token of no use, which is what a bad one is.
	var node string
	if err == nil {
		node, err = r.nodes.seal(reg)
	}
	switch {
	case err != nil:
		r.metrics.registration(label, "bad_token")
		r.reply(st, stanzaErr("modify", "bad-request"))
		return
	case label == "unknown":
		r.metrics.registration(label, "bad_form")
		r.reply(st, stanzaErr("modify", "bad-request"))
		return
	}
	// No address or device in the logs: the privacy policy promises the relay keeps nothing about who uses it.
	slog.Info("registered", "sandbox", reg.Sandbox)
	r.metrics.registration(label, "ok")
	c := answer("completed")
	c.Form = &dataForm{XMLName: xml.Name{Space: nsData, Local: "x"}, Type: "result", Fields: []formField{{Var: "node", Values: []string{node}}}}
	r.reply(st, c)
}

// publish is a notification from a user's server: it becomes an alert on the device the node names. The
// notification's summary (sender, body) is ignored, so none of it reaches Apple.
func (r *relay) publish(st stanza) {
	var ps struct {
		Publish struct {
			Node string `xml:"node,attr"`
		} `xml:"publish"`
	}
	if err := xml.Unmarshal(st.Inner, &ps); err != nil || ps.Publish.Node == "" {
		r.metrics.publish("bad_node")
		r.reply(st, stanzaErr("modify", "bad-request"))
		return
	}
	reg, err := r.nodes.open(ps.Publish.Node)
	if err != nil {
		r.metrics.publish("bad_node")
		r.reply(st, stanzaErr("cancel", "item-not-found"))
		return
	}
	// Prosody publishes as the user, ejabberd as the user's server.
	from := normalizeJID(st.From)
	if from != reg.Owner && from != domainOf(reg.Owner) {
		slog.Warn("publish from a stranger")
		r.metrics.publish("unauthorized")
		r.reply(st, stanzaErr("auth", "forbidden"))
		return
	}

	node := ps.Publish.Node
	if !r.schedule(node, reg) {
		// A push is already on its way, or comes at the window's end; that one is counted when it goes out.
		r.metrics.publish("coalesced")
		r.reply(st, nil)
		return
	}
	if e := r.pushed(node, reg, false); e != nil {
		r.reply(st, e)
		return
	}
	r.reply(st, nil)
}

// pushed pushes for reg, counts and logs how it went, and returns the reply for the publish behind it. A dead
// token is dropped from the throttle: a trailing push has no publish to answer, so the server's next publish is
// pushed at once and gets the item-not-found.
func (r *relay) pushed(node string, reg registration, trailing bool) *stanzaError {
	defer r.finished()
	log := slog.With("sandbox", reg.Sandbox)
	if trailing {
		log = log.With("trailing", true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := r.apns.push(ctx, reg)
	var refused *pushError
	outcome := ""
	if errors.As(err, &refused) {
		outcome = refused.outcome()
	}
	switch {
	case err == nil:
		if trailing {
			r.metrics.publish("trailing")
		} else {
			r.metrics.publish("sent")
		}
		log.Info("pushed")
		return nil
	case outcome == "gone":
		// The server drops a push target its app server says doesn't exist.
		r.metrics.publish("gone")
		log.Info("device gone", "reason", refused.Reason)
		r.forget(node)
		return stanzaErr("cancel", "item-not-found")
	case outcome == "too_many":
		r.metrics.publish("error")
		log.Warn("throttled by APNs")
		return stanzaErr("wait", "resource-constraint")
	}
	r.metrics.publish("error")
	log.Error("push failed", "err", err)
	return stanzaErr("wait", "internal-server-error")
}

// finished ends a push schedule promised.
func (r *relay) finished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy--
	if r.busy == 0 && r.idle != nil {
		close(r.idle)
		r.idle = nil
	}
}

// drain sends the trailing pushes now instead of at the end of their windows, and waits until ctx ends for them
// and for the pushes already on their way. Publishes after it are pushed at once. It is for shutdown, so neither
// the last publish of a burst nor one being pushed is lost.
func (r *relay) drain(ctx context.Context) {
	r.mu.Lock()
	r.draining = true
	for _, t := range r.recent {
		if t.timer != nil && t.timer.Stop() {
			t.timer.Reset(0)
		}
	}
	if r.busy == 0 {
		r.mu.Unlock()
		return
	}
	if r.idle == nil {
		r.idle = make(chan struct{})
	}
	idle := r.idle
	r.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
	}
}

// schedule decides whether a publish to node is pushed now (true). Otherwise a push to reg for the window's end
// is scheduled, unless one already is; either way the publish is absorbed. Each push it promises counts as busy
// until pushed finishes it.
func (r *relay) schedule(node string, reg registration) (now bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.window <= 0 {
		r.busy++
		return true
	}
	if r.recent == nil {
		r.recent = map[string]*throttle{}
	}
	at := time.Now()
	// Dropping the idle entries takes a pass over all of them: once a window is often enough.
	if at.Sub(r.lastSweep) > r.window {
		r.lastSweep = at
		for n, t := range r.recent {
			if t.idle(at, r.window) {
				delete(r.recent, n)
			}
		}
	}
	t := r.recent[node]
	if t != nil && t.timer != nil {
		return false
	}
	r.busy++
	switch {
	case t == nil:
		r.recent[node] = &throttle{last: at}
		return true
	case at.Sub(t.last) >= r.window || r.draining:
		t.last = at
		return true
	}
	t.timer = time.AfterFunc(t.last.Add(r.window).Sub(at), func() {
		r.mu.Lock()
		t.last, t.timer = time.Now(), nil
		r.mu.Unlock()
		r.pushed(node, reg, true)
	})
	return false
}

// forget drops node from the throttle. A trailing push scheduled meanwhile keeps its entry: it gets the same
// answer and drops it then.
func (r *relay) forget(node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.recent[node]; t != nil && t.timer == nil {
		delete(r.recent, node)
	}
}

// throttled counts the devices the throttle holds: inside their window, or with a trailing push pending.
func (r *relay) throttled() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, now := 0, time.Now()
	for _, t := range r.recent {
		if !t.idle(now, r.window) {
			n++
		}
	}
	return float64(n)
}

// iq is a reply: a result with payload (or none), or an error when the payload is a *stanzaError.
type iq struct {
	XMLName xml.Name `xml:"iq"`
	Type    string   `xml:"type,attr"`
	ID      string   `xml:"id,attr"`
	From    string   `xml:"from,attr"`
	To      string   `xml:"to,attr"`
	Payload any
}

// reply answers an iq: with payload (or nil) for a result, or with a *stanzaError for an error.
func (r *relay) reply(st stanza, payload any) {
	typ := "result"
	if _, ok := payload.(*stanzaError); ok {
		typ = "error"
	}
	out, err := xml.Marshal(iq{Type: typ, ID: st.ID, From: cmp.Or(st.To, r.domain), To: st.From, Payload: payload})
	if err != nil {
		slog.Warn("couldn't encode a reply", "err", err)
		return
	}
	if err := r.send(string(out)); err != nil {
		slog.Warn("couldn't reply", "err", err)
	}
}

// stanzaError is an <error/> element: the type says what the sender can do about it, the condition what went wrong.
type stanzaError struct {
	XMLName   xml.Name `xml:"error"`
	Type      string   `xml:"type,attr"`
	Condition struct {
		XMLName xml.Name
	}
}

func stanzaErr(typ, condition string) *stanzaError {
	e := &stanzaError{Type: typ}
	e.Condition.XMLName = xml.Name{Space: nsStanzas, Local: condition}
	return e
}

func domainOf(bare string) string {
	if i := strings.IndexByte(bare, '@'); i >= 0 {
		return bare[i+1:]
	}
	return bare
}
