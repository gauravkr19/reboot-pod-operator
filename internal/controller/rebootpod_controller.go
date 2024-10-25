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
	"os"
	"strconv"
	"time"

	vault "github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gauravkr19devv1alpha1 "github.com/gauravkr19/reboot-pod/api/v1alpha1"
)

// RebootPodReconciler reconciles a RebootPod object
type RebootPodReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	VaultURL string
	AuthPath string
	UseTLS   bool
}

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

	// Fetch the RebootPod CR
	var rebootPod gauravkr19devv1alpha1.RebootPod
	if err := r.Get(ctx, req.NamespacedName, &rebootPod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Get role from CR spec (mapped to the Vault role for static credentials)
	jwtRole := rebootPod.Spec.JwtRole
	vaultEndpointDB := rebootPod.Spec.VaultEndpointDB
	AuthPath := os.Getenv("AuthPath")

	// jwtToken, err := os.ReadFile("/home/cloud_user/my-controller/unseal/jwt_token")
	jwtToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Error(err, "unable to read ServiceAccount JWT token")
		return ctrl.Result{}, err
	}

	// JWT login to Vault
	authData := map[string]interface{}{
		"jwt":  string(jwtToken),
		"role": jwtRole,
	}

	// Authenticate with Vault and set token
	vaultClient := createVaultClient(ctx)
	secret, err := vaultClient.Logical().Write(AuthPath, authData)
	if err != nil || secret.Auth == nil {
		log.Error(err, "Vault JWT login failed")
		return ctrl.Result{}, err
	}
	// Set the Vault token from the authentication response
	vaultClient.SetToken(secret.Auth.ClientToken)

	// Query Vault for the specific role's database credentials
	creds, err := vaultClient.Logical().Read(vaultEndpointDB)
	if err != nil {
		log.Error(err, "failed to query Vault for database static credentials")
		return ctrl.Result{}, err
	}

	// Extract the ttl and last_vault_rotation
	ttl, err := strconv.Atoi(creds.Data["ttl"].(json.Number).String())
	if err != nil {
		log.Error(err, "failed to convert TTL to integer")
		return ctrl.Result{}, err
	}
	lastRotationStr := creds.Data["last_vault_rotation"].(string)
	lastRotation, err := time.Parse(time.RFC3339, lastRotationStr)
	if err != nil {
		log.Error(err, "failed to parse string time to time.Time")
	}

	log.Info("Fetched TTL and rotation info from Vault", "last_vault_rotation", lastRotation, "ttl", ttl)

	// TTL Expiry Check (TTL is 0 or just expired)
	if ttl == 0 || ttlExpired(lastRotation) {
		log.Info("TTL is 0, performing rollout restart")
		err := r.performRolloutRestart(ctx, &rebootPod)
		if err != nil {
			log.Error(err, "failed to perform rollout restart")
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 40 * time.Second}, nil
	}

	// TTL > 1 day: Requeue after 23 hours
	if ttl > 24*3600 {
		log.Info("TTL > 24h, requeueing after 23 hours", "ttl", ttl)
		return ctrl.Result{RequeueAfter: 23 * time.Hour}, nil
	}

	// TTL < 3s: Requeue every second
	if ttl < 3 {
		log.Info("TTL < 10s, requeueing every second", "ttl", ttl)
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}

	// TTL < 60s: Requeue after ttl/2
	if ttl < 60 {
		requeueInterval := time.Duration(ttl/2) * time.Second
		log.Info("TTL < 60s, requeueing after ttl/2", "ttl", ttl, "requeueInterval", requeueInterval)
		return ctrl.Result{RequeueAfter: requeueInterval}, nil
	}

	// Default case: Requeue based on the remaining TTL (keep checking in chunks)
	requeueInterval := time.Duration(ttl/2) * time.Second
	log.Info("Requeueing based on remaining TTL", "ttl", ttl, "requeueInterval", requeueInterval)
	return ctrl.Result{RequeueAfter: requeueInterval}, nil
}

// Create a Vault client
func createVaultClient(ctx context.Context) *vault.Client {
	log := log.FromContext(ctx)
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = os.Getenv("VaultURL")
	useTLSStr := os.Getenv("UseTLS")
	useTLS, _ := strconv.ParseBool(useTLSStr)
	vaultConfig.ConfigureTLS(&vault.TLSConfig{Insecure: useTLS})

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Error(err, "unable to create Vault client")
	}
	return vaultClient
}

// Check if the TTL might have expired based on last known rotation and current time
func ttlExpired(lastRotation time.Time) bool {
	// Example: If TTL is expected to expire in the last 30 seconds, consider it expired
	expirationBuffer := 3 * time.Second
	now := time.Now()
	// Check if the difference between now and the last known rotation time indicates expiration
	return now.Sub(lastRotation) < expirationBuffer
}

// performRolloutRestart handles the rollout restart logic with retry on conflict
func (r *RebootPodReconciler) performRolloutRestart(ctx context.Context, rebootPod *gauravkr19devv1alpha1.RebootPod) error {
	log := log.FromContext(ctx)

	for _, target := range rebootPod.Spec.RestartTargets {
		switch target.Kind {
		case "Deployment":
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var deployment appsv1.Deployment

				// Fetch the latest version of the Deployment
				if err := r.Get(ctx, types.NamespacedName{
					Namespace: rebootPod.Namespace, Name: target.Name}, &deployment); err != nil {
					log.Error(err, "Deployment not found", "name", target.Name)
					return err
				}

				// Annotate the Deployment to trigger rollout restart
				if deployment.Spec.Template.Annotations == nil {
					deployment.Spec.Template.Annotations = make(map[string]string)
				}
				deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

				// Attempt to update the Deployment
				if err := r.Update(ctx, &deployment); err != nil {
					log.Error(err, "failed to update Deployment for rollout restart", "name", target.Name)
					return err
				}

				log.Info("Successfully restarted Deployment", "name", target.Name)
				return nil
			})

			if err != nil {
				log.Error(err, "Error performing rollout restart for Deployment", "name", target.Name)
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
					log.Error(err, "failed to update StatefulSet for rollout restart", "name", target.Name)
					return err
				}

				log.Info("Successfully restarted StatefulSet", "name", target.Name)
				return nil
			})

			if err != nil {
				log.Error(err, "Error performing rollout restart for StatefulSet", "name", target.Name)
				return err
			}
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RebootPodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gauravkr19devv1alpha1.RebootPod{}).
		Complete(r)
}
