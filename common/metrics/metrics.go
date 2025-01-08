package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HealthCheckVSO = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "health_check_vso",
			Help: "Health check metrics for reboot pods, reflecting their current status.",
		},
		[]string{"rebootCompleted", "rolloutStatus", "failedResources", "vaultSyncStatus", "synchedSecret", "vaultDB", "namespace", "rebootPod", "workloads"},
	)
)

func RegisterMetrics() error {
	prometheus.MustRegister(HealthCheckVSO)

	http.Handle("/custom_metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":8082", nil); err != nil {
			panic(err)
		}
	}()
	return nil
}
