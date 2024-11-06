/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"text/tabwriter"
	"time"

	vault "github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gauravkr19devv1alpha1 "github.com/gauravkr19/reboot-pod/api/v1alpha1"
)

// RebootPodReconciler reconciles a RebootPod object
type RebootPodReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	VaultURL   string
	AuthPath   string
	UseTLS     bool
	Cache      map[string]TTLCacheEntry // cache to store TTLs of all the CRs and poll concurrently to check the expiration
	CacheMutex sync.Mutex               // Mutex for safe concurrent access to Cache
}

// TTLCacheEntry stores the expiration time and last rotation for each CR.
type TTLCacheEntry struct {
	Expiration   time.Time
	LastRotation time.Time
	Namespace    string //namespace of the CR
}

// // ANSI escape codes for colors and reset
// const (
// 	Reset = "\033[0m"
// 	Bold  = "\033[1m"
// 	Blue  = "\033[34m" // Or any color code of your choice
// )

// +kubebuilder:rbac:groups=gauravkr19.dev,resources=rebootpods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gauravkr19.dev,resources=rebootpods/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gauravkr19.dev,resources=rebootpods/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RebootPod object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *RebootPodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Update the cache with TTL and last rotation info
	if err := r.updateCache(ctx, req.Name, req.Namespace); err != nil {
		log.Error(err, "Failed to update cache in Reconcile", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, err
	}

	log.Info("Reconciled RebootPod and updated cache", "CR", req.Name)
	return ctrl.Result{RequeueAfter: 6 * time.Hour}, nil
}

// Create a Vault client
func (r *RebootPodReconciler) fetchTTLFromVault(ctx context.Context, name, namespace string) (int64, time.Time, error) {
	log := log.FromContext(ctx)

	// Retrieve the RebootPod object
	var rebootPod gauravkr19devv1alpha1.RebootPod
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rebootPod); err != nil {
		log.Error(err, "Failed to fetch RebootPod for Vault TTL check", "name", name, "namespace", namespace)
		return 0, time.Time{}, err
	}

	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = os.Getenv("VaultURL")
	useTLSStr := os.Getenv("UseTLS")
	useTLS, _ := strconv.ParseBool(useTLSStr)
	vaultConfig.ConfigureTLS(&vault.TLSConfig{Insecure: useTLS})

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Error(err, "unable to create Vault client")
	}

	// Get role from CR spec (mapped to the Vault role for static credentials)
	jwtRole := rebootPod.Spec.JwtRole
	vaultEndpointDB := rebootPod.Spec.VaultEndpointDB
	AuthPath := os.Getenv("AuthPath")

	// jwtToken, err := os.ReadFile("/home/cloud_user/my-controller/unseal/jwt_token")
	jwtToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Error(err, "unable to read ServiceAccount JWT token")
	}

	// JWT login to Vault
	authData := map[string]interface{}{
		"jwt":  string(jwtToken),
		"role": jwtRole,
	}

	// Authenticate with Vault and set token
	// vaultClient := createVaultClient(ctx)
	secret, err := vaultClient.Logical().Write(AuthPath, authData)
	if err != nil || secret.Auth == nil {
		log.Error(err, "Vault JWT/K8s login failed")
	}
	// Set the Vault token from the authentication response
	vaultClient.SetToken(secret.Auth.ClientToken)

	// Query Vault for the specific role's database credentials
	creds, err := vaultClient.Logical().Read(vaultEndpointDB)
	if err != nil {
		log.Error(err, "failed to query Vault for database static credentials")
	}

	// strconv.ParseInt the ttl string directly as an int64, The 10 specifies the base (decimal), and 64 specifies the bit size (int64). Unlike Atoi which gives int
	ttl, err := strconv.ParseInt(creds.Data["ttl"].(json.Number).String(), 10, 64)
	if err != nil {
		log.Error(err, "failed to convert TTL to integer")
	}
	lastRotationStr := creds.Data["last_vault_rotation"].(string)
	lastRotation, err := time.Parse(time.RFC3339, lastRotationStr)
	if err != nil {
		log.Error(err, "failed to parse string time to time.Time")
	}

	// log.Info("Fetched TTL and rotation info from Vault", "last_vault_rotation", lastRotation, "ttl", ttl)
	return ttl, lastRotation, err
}

// updateCache updates cache with CR as key and few ttributes as values of the map
func (r *RebootPodReconciler) updateCache(ctx context.Context, name, namespace string) error {
	log := log.FromContext(ctx)

	var rebootPod gauravkr19devv1alpha1.RebootPod
	if r.Cache == nil {
		r.Cache = make(map[string]TTLCacheEntry)
	}

	// Retrieve the latest RebootPod object
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rebootPod); err != nil {
		log.Error(err, "Failed to fetch RebootPod for cache update", "name", name, "namespace", namespace)
		return err
	}

	// Fetch TTL and last rotation from Vault
	ttl, lastRotation, err := r.fetchTTLFromVault(ctx, name, namespace)
	if err != nil {
		log.Error(err, "Failed to fetch TTL from Vault")
		return err
	}

	buffer := 400 * time.Millisecond
	expiration := time.Now().Add((time.Duration(ttl) * time.Second) + buffer)

	// Initialize a tabwriter with minimum width, padding, and alignment to display the cache
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	// Print table headers
	fmt.Fprintln(w, "CR Name\tNamespace\tTTL Expiration\tLast Rotation")
	// header := fmt.Sprintf("%s%sCR Name\tNamespace\tExpiration\tLast Rotation%s", Bold, Blue, Reset)
	// fmt.Fprintln(w, header)

	// Update cache with TTL and last rotation info
	r.CacheMutex.Lock()
	r.Cache[rebootPod.Name] = TTLCacheEntry{
		Expiration:   expiration,
		LastRotation: lastRotation,
		Namespace:    rebootPod.Namespace,
	}

	for name, entry := range r.Cache {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, entry.Namespace, entry.Expiration.Format("2006-01-02 15:04:05"), entry.LastRotation.Format("2006-01-02 15:04:05"))
	}
	r.CacheMutex.Unlock()
	fmt.Println()
	w.Flush()
	fmt.Println()

	log.Info("Cache Updated")
	return nil
}

// performRolloutRestart handles the rollout restart logic with retry on conflict
func (r *RebootPodReconciler) performRolloutRestart(ctx context.Context, name string, namespace string) error {
	log := log.FromContext(ctx)
	var rebootPod gauravkr19devv1alpha1.RebootPod

	// Retrieve the latest RebootPod object
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rebootPod); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("RebootPod not found, may have been deleted", "name", name, "namespace", namespace)
			return nil
		}
		log.Error(err, "Failed to fetch RebootPod", "name", name, "namespace", namespace)
		return err
	}

	for _, target := range rebootPod.Spec.RestartTargets {
		switch target.Kind {
		case "Deployment":
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var deployment appsv1.Deployment

				// Fetch the latest version of the Deployment
				if err := r.Get(ctx, types.NamespacedName{
					Namespace: rebootPod.Namespace, Name: target.Name}, &deployment); err != nil {
					log.Error(err, "Deployment not found", "name", target.Name)
					// return err
				}

				// Annotate the Deployment to trigger rollout restart
				if deployment.Spec.Template.Annotations == nil {
					deployment.Spec.Template.Annotations = make(map[string]string)
				}
				deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

				// Attempt to update the Deployment
				if err := r.Update(ctx, &deployment); err != nil {
					log.Error(err, "failed to update Deployment for rollout restart", "name", target.Name, "namespace", namespace)
					return err
				}

				log.Info("Successfully restarted Deployment", "name", target.Name, "namespace", namespace)
				return nil
			})

			if err != nil {
				log.Error(err, "Error performing rollout restart for Deployment", "name", target.Name, "namespace", namespace)
				return err
			}

		case "StatefulSet":
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var statefulSet appsv1.StatefulSet

				// Fetch the latest version of the StatefulSet
				if err := r.Get(ctx, types.NamespacedName{
					Namespace: rebootPod.Namespace, Name: target.Name}, &statefulSet); err != nil {
					log.Error(err, "StatefulSet not found", "name", target.Name)
					return err
				}

				// Annotate the StatefulSet to trigger rollout restart
				if statefulSet.Spec.Template.Annotations == nil {
					statefulSet.Spec.Template.Annotations = make(map[string]string)
				}
				statefulSet.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

				// Attempt to update the StatefulSet
				if err := r.Update(ctx, &statefulSet); err != nil {
					log.Error(err, "failed to update StatefulSet for rollout restart", "name", target.Name, "namespace", namespace)
					return err
				}

				log.Info("Successfully restarted StatefulSet", "name", target.Name, "namespace", namespace)
				return nil
			})

			if err != nil {
				log.Error(err, "Error performing rollout restart for StatefulSet", "name", target.Name, "namespace", namespace)
				return err
			}
		}
	}
	return nil
}

// Check if the TTL might have expired based on last known rotation and current time
func ttlExpired(lastRotation time.Time) bool {
	// TTL expiry missed by 4s, consider it expired
	expirationBuffer := 4 * time.Second
	now := time.Now()
	// Check if the difference between now and the last known rotation time indicates expiration
	return now.Sub(lastRotation) < expirationBuffer
}

// StartPollingLoop function runs continuously in a background goroutine, checking the TTLs in the cache every minute.
func (r *RebootPodReconciler) StartPollingLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done(): // Check if context is canceled
			return // Stop the polling loop if the context is done
		case <-ticker.C: // channel ticks at regular intervals

			for name, entry := range r.Cache { // Iterate over each CR in the cache

				// 1st check, Validate TTL Expiration based on ttl+expiration
				if time.Now().After(entry.Expiration) {

					ttl, lastRotation, err := r.fetchTTLFromVault(ctx, name, entry.Namespace)
					if err != nil {
						log.Log.WithValues("name", name, "namespace", entry.Namespace).Error(err, "Failed to confirm TTL from Vault")
						continue // Skip this iteration if the Vault call fails
					}

					// 2nd check, Validate TTL again based on TTL OR last_vault_rotation
					if ttl == 0 || ttlExpired(lastRotation) {
						log.Log.WithValues("name", name, "namespace", entry.Namespace, "ttl", ttl).Info("TTL expired, initiating rollout restart")

						err := r.performRolloutRestart(ctx, name, entry.Namespace)
						if err != nil {
							log.Log.WithValues("name", name, "namespace", entry.Namespace, "error", err).Error(err, "Failed to perform rollout restart")
						} else {
							log.Log.Info("Deleting CR from cache", "CR", name)
							r.CacheMutex.Lock() // Lock the cache for safe concurrent access
							delete(r.Cache, name)
							r.CacheMutex.Unlock()
							log.Log.Info("Updating the cache with TTL and last rotation info", "CR", name)
							if err := r.updateCache(ctx, name, entry.Namespace); err != nil {
								log.Log.Error(err, "Failed to update TTL cache after reboot", "name", name, "namespace", entry.Namespace)
							}
						}
					}
				}
			}
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *RebootPodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Start polling loop in a goroutine
	go r.StartPollingLoop(context.Background())

	return ctrl.NewControllerManagedBy(mgr).
		For(&gauravkr19devv1alpha1.RebootPod{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // Trigger only on creation or update
		Complete(r)
}
