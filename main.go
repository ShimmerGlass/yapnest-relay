// yapnest-relay is Yapnest's push app server (XEP-0357): an XMPP component that turns the notifications users'
// servers publish into APNs alerts.
package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var missing error
	need := func(name string) string {
		v := os.Getenv(name)
		if v == "" && missing == nil {
			missing = fmt.Errorf("%s isn't set", name)
		}
		return v
	}
	domain, server, secret := need("RELAY_DOMAIN"), need("RELAY_SERVER"), need("RELAY_COMPONENT_SECRET")
	relayKey, keyID, teamID := need("RELAY_KEY"), need("APNS_KEY_ID"), need("APNS_TEAM_ID")
	if missing != nil {
		return missing
	}
	topic := cmp.Or(os.Getenv("APNS_TOPIC"), "fr.yapnest.app")

	// The key, as the .p8's contents or a path to it.
	p8 := []byte(os.Getenv("APNS_KEY"))
	if len(p8) == 0 {
		path := os.Getenv("APNS_KEY_FILE")
		if path == "" {
			return fmt.Errorf("set APNS_KEY or APNS_KEY_FILE")
		}
		var err error
		if p8, err = os.ReadFile(path); err != nil {
			return err
		}
	}
	key, err := parseP8(p8)
	if err != nil {
		return err
	}
	rawKey, err := base64.StdEncoding.DecodeString(relayKey)
	if err != nil {
		return fmt.Errorf("RELAY_KEY isn't base64: %w", err)
	}
	nodes, err := newSealer(rawKey)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Metrics are served only where the deploy asks for them, so nothing changes for the ones that don't.
	var m *metrics
	var metricsLn net.Listener
	if addr := os.Getenv("RELAY_METRICS_ADDR"); addr != "" {
		if metricsLn, err = net.Listen("tcp", addr); err != nil {
			return fmt.Errorf("RELAY_METRICS_ADDR: %w", err)
		}
		m = newMetrics()
	}
	c := &component{domain: domain, server: server, secret: secret, metrics: m}
	r := &relay{
		domain: domain,
		nodes:  nodes,
		apns: &apns{
			key: key, keyID: keyID, teamID: teamID, topic: topic,
			production: apnsProduction, sandbox: apnsSandbox,
			client:  &http.Client{Timeout: 30 * time.Second},
			metrics: m,
		},
		send:    c.send,
		window:  pushWindow,
		metrics: m,
	}
	if m != nil {
		m.trackThrottle(r)
		go serveMetrics(ctx, metricsLn, m.handler())
	}
	c.handle = r.handle
	slog.Info("starting", "domain", domain, "server", server, "topic", topic)
	c.run(ctx)
	// Docker waits 10 s after SIGTERM. The last publish of a burst is still waiting for its window: push it now.
	drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.drain(drain)
	return nil
}
