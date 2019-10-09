package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func wrapPrometheusMetrics(handler http.Handler) http.Handler {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "A counter for requests to the wrapped handler.",
		},
		[]string{"code", "method"},
	)
	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: []float64{.25, .5, 0.75, 1, 2.5, 5, 10},
		},
		[]string{"handler", "method"},
	)
	inFlight := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "in_flight_requests",
		Help: "A gauge of requests currently being served by the wrapped handler.",
	})
	requestSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "request_size_bytes",
			Help:    "A histogram of request sizes.",
			Buckets: []float64{200, 500, 900, 1500, 4100, 8200, 16400, 32800},
		},
		[]string{},
	)
	responseSize := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "response_size_bytes",
			Help:    "A histogram of response sizes for requests.",
			Buckets: []float64{200, 500, 900, 1500, 4100, 8200, 16400, 32800},
		},
		[]string{},
	)
	timeToWriteHeader := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "time_to_write_header",
			Help:    "A histogram of time to write heaer.",
			Buckets: []float64{0.25, 0.5, 0.75, 1, 2.5, 5, 10},
		},
		[]string{},
	)

	// Register all of the metrics in the standard registry.
	prometheus.MustRegister(counter, duration, inFlight, requestSize, responseSize, timeToWriteHeader)

	return promhttp.InstrumentHandlerCounter(counter,
		promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"handler": "pull"}),
			promhttp.InstrumentHandlerInFlight(inFlight,
				promhttp.InstrumentHandlerRequestSize(requestSize,
					promhttp.InstrumentHandlerResponseSize(responseSize,
						promhttp.InstrumentHandlerTimeToWriteHeader(timeToWriteHeader, handler))))))
}
