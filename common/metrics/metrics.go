package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	gauravkr19devv1alpha1 "github.com/gauravkr19/reboot-pod/api/v1alpha1"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HealthCheckVSO = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "health_check_vso",
			Help: "Health check metrics for reboot pods, reflecting their current status.",
		},
		[]string{"rolloutStatus", "failedResourcesCount", "failedResourcesNames", "vaultSyncStatus", "synchedSecret", "vaultEndpointDB", "eventsCount", "namespace", "rebootPod", "workloads"},
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

// UpdateMetrics updates the HealthCheckVSO metric with the current RebootPod status.
func UpdateMetrics(ctx context.Context, rebootPod *gauravkr19devv1alpha1.RebootPod) {
	// Extract fields from rebootPod
	rolloutStatus := rebootPod.Status.RolloutStatus.State

	// Compute failed resources count and names
	failedCount := 0
	var failedNames []string
	if rebootPod.Status.RolloutStatus.FailedHealthChecks != nil {
		failedCount = len(rebootPod.Status.RolloutStatus.FailedHealthChecks)
		for _, ref := range rebootPod.Status.RolloutStatus.FailedHealthChecks {
			failedNames = append(failedNames, ref.Name)
		}
	}
	failedCountStr := fmt.Sprintf("%d", failedCount)
	failedNamesStr := "None"
	if len(failedNames) > 0 {
		failedNamesStr = strings.Join(failedNames, ", ")
	}

	// Vault sync status and secret name
	vaultSyncStatus := rebootPod.Status.VaultSyncStatus.State
	synchedSecret := "None"
	if rebootPod.Status.VaultSyncStatus.SynchedSecret != nil && len(rebootPod.Status.VaultSyncStatus.SynchedSecret) > 0 {
		synchedSecret = rebootPod.Status.VaultSyncStatus.SynchedSecret[0].Name
	}

	// Count event issues (if any)
	eventIssuesCount := 0
	if rebootPod.Status.EventIssues != nil {
		eventIssuesCount = len(rebootPod.Status.EventIssues)
	}
	eventIssuesCountStr := fmt.Sprintf("%d", eventIssuesCount)

	// Concatenate restart target names from spec
	var rtNames []string
	for _, target := range rebootPod.Spec.RestartTargets {
		rtNames = append(rtNames, target.Name)
	}
	restartTargetsLabel := strings.Join(rtNames, ", ")

	// Update the metric using the appropriate label values.
	HealthCheckVSO.WithLabelValues(
		rolloutStatus,
		failedCountStr,
		failedNamesStr,
		vaultSyncStatus,
		synchedSecret,
		rebootPod.Spec.VaultEndpointDB,
		eventIssuesCountStr,
		rebootPod.Namespace,
		rebootPod.Name,
		restartTargetsLabel,
	).Set(1)
}
