// Package observability provides Prometheus metrics of the service.
package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics groups the collectors used by the HTTP layer. A dedicated registry
// (instead of the global one) keeps tests isolated.
type Metrics struct {
	Registry *prometheus.Registry

	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	InFlight          prometheus.Gauge
	RateLimitedTotal  *prometheus.CounterVec
	AuthFailuresTotal *prometheus.CounterVec
	PanicsTotal       prometheus.Counter
}

// NewMetrics creates and registers all collectors, including Go runtime and
// process metrics.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "threat_exchange_http_requests_total",
			Help: "HTTP requests processed, by method, route and status code.",
		}, []string{"method", "route", "code"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "threat_exchange_http_request_duration_seconds",
			Help:    "HTTP request latency, by method and route.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"method", "route"}),
		InFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "threat_exchange_http_requests_in_flight",
			Help: "HTTP requests currently being processed.",
		}),
		RateLimitedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "threat_exchange_rate_limited_total",
			Help: "Requests rejected by the rate limiter, by scope (ip, key).",
		}, []string{"scope"}),
		AuthFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "threat_exchange_auth_failures_total",
			Help: "Failed authentication or authorization attempts, by reason.",
		}, []string{"reason"}),
		PanicsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "threat_exchange_panics_recovered_total",
			Help: "Panics recovered in HTTP handlers.",
		}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.RequestsTotal, m.RequestDuration, m.InFlight,
		m.RateLimitedTotal, m.AuthFailuresTotal, m.PanicsTotal,
	)
	return m
}

// Handler returns the /metrics endpoint handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
