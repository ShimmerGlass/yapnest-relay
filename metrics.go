package main

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// buildVersion is the release tag, set by the image build (-ldflags "-X main.buildVersion=…"): the image
// is built without the git history Go would take its own version from.
var buildVersion string

// buildRevision is the commit, set the same way (-X main.buildRevision=…).
var buildRevision string

// The privacy policy says the relay keeps nothing about who uses it, so a metric's labels are fixed words from
// the lists below and never anything the relay was told: no address, server domain, device token or node, and
// nothing derived from them, hashes included. Counts of them, like the devices in the throttle, say nothing about
// who they are and are fine. Counters that don't fit those words don't get added.
var (
	environments        = []string{"sandbox", "production"}
	registrationResults = []string{"ok", "bad_token", "bad_form"}
	publishResults      = []string{"sent", "coalesced", "trailing", "unauthorized", "bad_node", "gone", "error"}
	apnsOutcomes        = []string{"ok", "bad_request", "forbidden", "gone", "too_many", "server_error", "network_error"}
	connectResults      = []string{"ok", "error"}
)

// metrics is what the relay counts. Its counting and recording methods do nothing on a nil *metrics, so code
// built without one (most of the tests) needn't care; handler needs one.
type metrics struct {
	reg           *prometheus.Registry
	registrations *prometheus.CounterVec
	publishes     *prometheus.CounterVec
	apnsRequests  *prometheus.CounterVec
	apnsDuration  *prometheus.HistogramVec
	connects      *prometheus.CounterVec

	connected atomic.Bool // for /healthz, which shouldn't have to parse the gauge
}

// newMetrics registers the relay's metrics, and Go's and the process's own, on a registry of its own, which keeps
// the global default's collectors out of the output.
func newMetrics() *metrics {
	m := &metrics{
		reg: prometheus.NewRegistry(),
		registrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "yapnest_relay_registrations_total",
			Help: "Device registrations by APNs environment (unknown when the form didn't name a valid one) and result.",
		}, []string{"environment", "result"}),
		publishes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "yapnest_relay_publishes_total",
			Help: "Publishes from users' servers by result. Coalesced ones were absorbed by a push in the window; trailing counts the pushes sent at the end of one.",
		}, []string{"result"}),
		apnsRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "yapnest_relay_apns_requests_total",
			Help: "Requests to APNs by environment and outcome.",
		}, []string{"environment", "outcome"}),
		apnsDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "yapnest_relay_apns_request_duration_seconds",
			Help:    "How long APNs requests took, failed ones included.",
			Buckets: []float64{0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"environment"}),
		connects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "yapnest_relay_component_connects_total",
			Help: "Attempts to connect to the XMPP server as a component, by result.",
		}, []string{"result"}),
	}
	connectedGauge := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "yapnest_relay_component_connected",
		Help: "1 while the component is connected to the XMPP server, 0 otherwise.",
	}, func() float64 {
		if m.connected.Load() {
			return 1
		}
		return 0
	})
	// Every series exists from the start, so a rate() over one that hasn't happened yet isn't empty.
	for _, env := range append(environments, "unknown") {
		for _, result := range registrationResults {
			m.registrations.WithLabelValues(env, result)
		}
	}
	for _, result := range publishResults {
		m.publishes.WithLabelValues(result)
	}
	for _, env := range environments {
		for _, outcome := range apnsOutcomes {
			m.apnsRequests.WithLabelValues(env, outcome)
		}
		m.apnsDuration.WithLabelValues(env)
	}
	for _, result := range connectResults {
		m.connects.WithLabelValues(result)
	}

	var mainVersion, vcsRevision string
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "(devel)" {
			mainVersion = v
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				vcsRevision = s.Value
			}
		}
	}
	version := cmp.Or(buildVersion, mainVersion, "unknown")
	revision := cmp.Or(short(buildRevision), short(vcsRevision), "unknown")
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "yapnest_relay_build_info",
		Help:        "The relay's version and commit, always 1.",
		ConstLabels: prometheus.Labels{"version": version, "revision": revision},
	})
	buildInfo.Set(1)

	m.reg.MustRegister(m.registrations, m.publishes, m.apnsRequests, m.apnsDuration, m.connects, connectedGauge, buildInfo,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// short is the first 12 characters of a commit id, like git's abbreviation.
func short(revision string) string {
	return revision[:min(len(revision), 12)]
}

// trackThrottle exposes how many devices the throttle holds: inside their window, or waiting for a trailing push.
// It's a count only; the nodes stay in the relay.
func (m *metrics) trackThrottle(r *relay) {
	if m == nil {
		return
	}
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "yapnest_relay_throttled_devices",
		Help: "Devices inside their push window or with a trailing push pending.",
	}, r.throttled))
}

func (m *metrics) registration(env, result string) {
	if m != nil {
		m.registrations.WithLabelValues(env, result).Inc()
	}
}

func (m *metrics) publish(result string) {
	if m != nil {
		m.publishes.WithLabelValues(result).Inc()
	}
}

func (m *metrics) apnsRequest(env, outcome string, took time.Duration) {
	if m != nil {
		m.apnsRequests.WithLabelValues(env, outcome).Inc()
		m.apnsDuration.WithLabelValues(env).Observe(took.Seconds())
	}
}

func (m *metrics) connect(result string) {
	if m != nil {
		m.connects.WithLabelValues(result).Inc()
	}
}

func (m *metrics) setConnected(up bool) {
	if m == nil {
		return
	}
	m.connected.Store(up)
}

// handler serves /metrics, and /healthz, which says whether the component is connected so a container
// check can tell a relay that can't receive publishes from one that can.
func (m *metrics) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if m.connected.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mux
}

// serveMetrics serves h on ln until ctx ends.
func serveMetrics(ctx context.Context, ln net.Listener, h http.Handler) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("serving metrics", "addr", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("metrics server stopped", "err", err)
	}
}
