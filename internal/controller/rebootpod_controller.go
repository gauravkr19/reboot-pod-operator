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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	vault "github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gauravkr19devv1alpha1 "github.com/gauravkr19/reboot-pod/api/v1alpha1"
	"github.com/gauravkr19/reboot-pod/common/metrics"
)

// RebootPodReconciler reconciles a RebootPod object
type RebootPodReconciler struct {
	client.Client                               // controller-runtime client.Client embedded directly
	DynamicClient             dynamic.Interface // client-go dynamic client
	Scheme                    *runtime.Scheme
	VaultURL                  string
	AuthPath                  string
	UseTLS                    bool
	Cache                     map[string]TTLCacheEntry // cache to store TTLs of all the CRs and poll concurrently to check the expiration
	CacheMutex                sync.Mutex
	HealthCheckMutex          sync.Mutex                                                 // Mutex for safe concurrent access to Cache
	HealthCheckCache          sync.Map                                                   // Map of enqueued resources by NamespacedName
	ProcessedResourceVersions sync.Map                                                   // Map to track last processed ResourceVersion
	Queue                     workqueue.TypedRateLimitingInterface[types.NamespacedName] // Work Queue for rollout-restart
	HealthCheckQueue          workqueue.TypedRateLimitingInterface[types.NamespacedName] // work queue for health checks
}

// TTLCacheEntry stores the expiration time and last rotation for each CR.
type TTLCacheEntry struct {
	Expiration   time.Time
	LastRotation time.Time
	Namespace    string //namespace of the CR
}

// Define the action type for the rollout handler
type RolloutAction int

const (
	ActionRestart RolloutAction = iota
	// ActionCheckStatus
)

func NewRebootPodReconciler(client client.Client, dynamicClient dynamic.Interface, scheme *runtime.Scheme, vaultURL, authPath string, useTLS bool) *RebootPodReconciler {
	return &RebootPodReconciler{
		Client:           client,
		DynamicClient:    dynamicClient,
		Scheme:           scheme,
		Cache:            make(map[string]TTLCacheEntry),
		Queue:            workqueue.NewTypedRateLimitingQueue[types.NamespacedName](workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName]()),
		HealthCheckQueue: workqueue.NewTypedRateLimitingQueue[types.NamespacedName](workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName]()),
		VaultURL:         vaultURL,
		AuthPath:         authPath,
		UseTLS:           useTLS,
	}
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
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch

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

	// Fetch the RebootPod instance
	var rebootPod gauravkr19devv1alpha1.RebootPod
	if err := r.Get(ctx, req.NamespacedName, &rebootPod); err != nil {
		if errors.IsNotFound(err) {
			log.Info("RebootPod resource not found. Ignoring since it must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to fetch RebootPod")
		return ctrl.Result{}, err
	}

	_, _, username, password, err := r.fetchTTLFromVault(ctx, req.Name, req.Namespace)
	if err != nil {
		log.Error(err, "Failed to fetch Vault credentials")
		return ctrl.Result{}, err
	}

	secretName, err := r.vaultSyncStatus(ctx, &rebootPod, username, password)
	if err != nil {
		rebootPod.Status.VaultSyncStatus = gauravkr19devv1alpha1.VaultSync{
			State: "Failure",
			SynchedSecret: []corev1.ObjectReference{
				{Name: "NoMatchingSecret", Namespace: rebootPod.Namespace},
			},
		}
	} else {
		rebootPod.Status.VaultSyncStatus = gauravkr19devv1alpha1.VaultSync{
			State: "Success",
			SynchedSecret: []corev1.ObjectReference{
				{Name: secretName, Namespace: rebootPod.Namespace},
			},
		}
	}

	if err := r.Status().Update(ctx, &rebootPod); err != nil {
		log.Error(err, "Failed to update RebootPod status")
		return ctrl.Result{}, err
	}

	log.Info("Reconciled RebootPod and updated cache", "CR", req.Name)
	return ctrl.Result{RequeueAfter: 6 * time.Hour}, nil
}

// Create a Vault client
func (r *RebootPodReconciler) fetchTTLFromVault(ctx context.Context, name, namespace string) (int64, time.Time, string, string, error) {
	log := log.FromContext(ctx)

	// Retrieve the RebootPod object
	var rebootPod gauravkr19devv1alpha1.RebootPod
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rebootPod); err != nil {
		log.Error(err, "Failed to fetch RebootPod for Vault TTL check", "name", name, "namespace", namespace)
		return 0, time.Time{}, "", "", err
	}

	vaultConfig := vault.DefaultConfig()
	// Configure TLS settings
	tlsConfig := &vault.TLSConfig{}

	vaultConfig.Address = os.Getenv("VaultURL")
	useTLSStr := os.Getenv("UseTLS")
	useTLS, err := strconv.ParseBool(useTLSStr)
	if err != nil {
		log.Error(err, "Error parsing UseTLS")
	}

	if useTLS {
		// Check if VAULT_CACERT is provided
		caCertPath := os.Getenv("VAULT_CACERT")
		if caCertPath != "" {
			// Load CA certificate
			caCert, err := os.ReadFile(caCertPath)
			if err != nil {
				log.Error(err, "Failed to read CA certificate", "CA Path", caCertPath)
			}

			// Create a certificate pool and append the CA certificate
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				log.Info("Failed to append CA certificate to pool")
			}

			// Set RootCAs for TLS configuration
			tlsConfig.CACert = caCertPath
		} else {
			// Enable InsecureSkipVerify if no CA certificate is provided
			tlsConfig.Insecure = true
			log.Info("No CA certificate provided. Using InsecureSkipVerify=true for TLS.")
		}
	} else {
		log.Info("TLS is disabled.")
	}

	// Apply TLS configuration to Vault client
	if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
		log.Error(err, "Error configuring TLS for Vault")
	}

	// vaultConfig.ConfigureTLS(&vault.TLSConfig{Insecure: useTLS})
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Error(err, "unable to create Vault client")
	}

	// Get role from CR spec (mapped to the Vault role for static credentials)
	jwtRole := rebootPod.Spec.JwtRole
	vaultEndpointDB := rebootPod.Spec.VaultEndpointDB
	AuthPath := os.Getenv("AuthPath")

	jwtToken, err := os.ReadFile("/home/cloud_user/my-controller/unseal/jwt_token")
	// jwtToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
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

	username := creds.Data["username"].(string)
	password := creds.Data["password"].(string)

	// log.Info("Fetched TTL and rotation info from Vault", "last_vault_rotation", lastRotation, "ttl", ttl)
	return ttl, lastRotation, username, password, err
}

// Modified handleRollout function to handle both restart and status check
func (r *RebootPodReconciler) handleRollout(ctx context.Context, name string, namespace string, actionType RolloutAction) error {
	log := log.FromContext(ctx)
	var rebootPod gauravkr19devv1alpha1.RebootPod

	// Retrieve the latest RebootPod object
	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rebootPod); err != nil {
		if errors.IsNotFound(err) {
			log.Info("RebootPod not found, may have been deleted", "name", name, "namespace", namespace)
			return nil
		}
		log.Error(err, "Failed to fetch RebootPod", "name", name, "namespace", namespace)
		return err
	}

	// Loop over the targets in the RebootPod spec and either restart or check status
	for _, target := range rebootPod.Spec.RestartTargets {
		if actionType == ActionRestart {
			switch target.Kind {
			case "Deployment":
				var deployment appsv1.Deployment
				if err := r.Get(ctx, types.NamespacedName{Namespace: rebootPod.Namespace, Name: target.Name}, &deployment); err != nil {
					log.Error(err, "Deployment not found", "name", target.Name, "namespace", rebootPod.Namespace)
					continue
				}
				if err := r.annotateAndRestartDeployment(ctx, &deployment); err != nil {
					return err
				}
				log.Info("Rollout-Restart of Deployment complete", "deployment", target.Name, "namespace", rebootPod.Namespace)

			case "StatefulSet":
				var statefulSet appsv1.StatefulSet
				if err := r.Get(ctx, types.NamespacedName{Namespace: rebootPod.Namespace, Name: target.Name}, &statefulSet); err != nil {
					log.Error(err, "StatefulSet not found", "name", target.Name, "namespace", rebootPod.Namespace)
					continue
				}
				if err := r.annotateAndRestartStatefulSet(ctx, &statefulSet); err != nil {
					return err
				}
				log.Info("Rollout-Restart of StatefulSet complete", "statefulset", target.Name, "namespace", rebootPod.Namespace)
			}
		}
		// After finishing rollout restart, trigger the informer for status checks on targets
		restartTargets := r.getRestartTargets(&rebootPod)
		r.SetupInformerForStatusCheck(ctx, namespace, restartTargets)
	}
	// Cache update after a successful restart or status check
	r.CacheMutex.Lock()
	delete(r.Cache, name)
	r.CacheMutex.Unlock()

	log.Info("Updating the cache with TTL and last rotation info", "CR", name)
	if err := r.updateCache(ctx, name, namespace); err != nil {
		log.WithValues("name", name, "namespace", namespace).Error(err, "Failed to update TTL cache after reboot")
	}
	return nil
}

// Separate functions for annotating and restarting
func (r *RebootPodReconciler) annotateAndRestartDeployment(ctx context.Context, deployment *appsv1.Deployment) error {
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = make(map[string]string)
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
	return r.Update(ctx, deployment)
}

func (r *RebootPodReconciler) annotateAndRestartStatefulSet(ctx context.Context, statefulSet *appsv1.StatefulSet) error {
	if statefulSet.Spec.Template.Annotations == nil {
		statefulSet.Spec.Template.Annotations = make(map[string]string)
	}
	statefulSet.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
	return r.Update(ctx, statefulSet)
}

// getRestartTargets converts rebootPod.Spec.RestartTargets into []corev1.ObjectReference type
func (r *RebootPodReconciler) getRestartTargets(rebootPod *gauravkr19devv1alpha1.RebootPod) []corev1.ObjectReference {
	targets := make([]corev1.ObjectReference, len(rebootPod.Spec.RestartTargets))
	for i, target := range rebootPod.Spec.RestartTargets {
		targets[i] = corev1.ObjectReference{
			Kind:      target.Kind,
			Name:      target.Name,
			Namespace: rebootPod.Namespace,
		}
	}
	return targets
}

// SetupInformerForStatusCheck sets up the dynamic informer for monitoring rollout status
func (r *RebootPodReconciler) SetupInformerForStatusCheck(ctx context.Context, namespace string, restartTargets []corev1.ObjectReference) {

	// Set up the dynamic informer factory
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(r.DynamicClient, time.Minute, namespace, nil)

	// Configure informers for Deployment and StatefulSet resources
	deploymentResource := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	statefulSetResource := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}

	deploymentInformer := factory.ForResource(deploymentResource).Informer()
	statefulSetInformer := factory.ForResource(statefulSetResource).Informer()

	// Add event handlers that only monitor specific targets
	deploymentInformer.AddEventHandler(r.getResourceEventHandler(namespace, restartTargets))
	statefulSetInformer.AddEventHandler(r.getResourceEventHandler(namespace, restartTargets))

	// Wait until the informer has fully synced before processing queue items
	// Wait for cache sync in a separate goroutine to avoid blocking
	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), deploymentInformer.HasSynced, statefulSetInformer.HasSynced) {
			log.Log.Error(fmt.Errorf("failed to sync cache"), "Informer caches not synchronized")
		} else {
			log.Log.Info("Informer caches synced successfully")
		}
	}()

	// Start the informers
	go deploymentInformer.Run(ctx.Done())
	go statefulSetInformer.Run(ctx.Done())
}

// Helper to create an event handler for tracking rollout status
func (r *RebootPodReconciler) getResourceEventHandler(namespace string, restartTargets []corev1.ObjectReference) cache.ResourceEventHandler {
	mux := &sync.RWMutex{}
	return cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			mux.RLock()
			defer mux.RUnlock()
			// oldU := oldObj.(*unstructured.Unstructured)
			newU := newObj.(*unstructured.Unstructured)

			// Get ResourceVersion of new object
			newRV := newU.GetResourceVersion()
			key := fmt.Sprintf("%s/%s", newU.GetNamespace(), newU.GetName())

			// Check if the ResourceVersion is already processed
			if lastRV, ok := r.ProcessedResourceVersions.Load(key); ok && lastRV == newRV {
				// log.Log.V(1).Info("Skipping event: ResourceVersion unchanged", "Name", newU.GetName(), "Namespace", newU.GetNamespace(), "ResourceVersion", newRV)
				return
			}

			// Update the cache with the new ResourceVersion
			r.ProcessedResourceVersions.Store(key, newRV)

			// Process only relevant targets
			for _, target := range restartTargets {
				if target.Name == newU.GetName() && target.Namespace == namespace && target.Kind == newU.GetKind() {
					r.enqueueResourceIfMonitored(newObj, namespace, restartTargets)
					break
				}
			}
		},
	}
}

// enqueueResourceIfMonitored enqueues the resource only if it's in RestartTargets and replicas match
func (r *RebootPodReconciler) enqueueResourceIfMonitored(obj interface{}, namespace string, restartTargets []corev1.ObjectReference) {
	u := obj.(*unstructured.Unstructured)
	name := u.GetName()
	const checkInterval = 5 * time.Minute // Control log frequency

	for _, target := range restartTargets {
		if target.Name == name && target.Namespace == namespace && target.Kind == u.GetKind() {

			// Check replica status to avoid redundant queuing
			updatedReplicas, _, _ := unstructured.NestedInt64(u.Object, "status", "updatedReplicas")
			desiredReplicas, _, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")

			namespacedName := types.NamespacedName{Name: name, Namespace: namespace}

			// Only enqueue if the item is unhealthy
			if updatedReplicas != desiredReplicas {
				// Avoid re-queuing if already enqueued
				if _, loaded := r.HealthCheckCache.LoadOrStore(namespacedName, time.Now()); !loaded {
					log.Log.Info("Adding to HealthCheckQueue for monitoring", "Name", name, "Namespace", namespace)
					r.HealthCheckQueue.AddAfter(namespacedName, time.Minute) // Add to health-check queue
				}
				// else {
				// 	log.Log.Info("Resource already enqueued, skipping", "Name", name, "Namespace", namespace)
				// }
			} else {
				// Check if sufficient time has passed before logging and deleting from the cache
				if lastChecked, ok := r.HealthCheckCache.Load(namespacedName); ok {
					if time.Since(lastChecked.(time.Time)) >= checkInterval {
						log.Log.Info("Resource is healthy, removed from HealthCheckCache", "Name", name, "Namespace", namespace)
						r.HealthCheckCache.Delete(namespacedName)
					}
				}
			}
		}
	}
}

// checkDeploymentStatus checks the rollout status of a specific Deployment and logs.
func (r *RebootPodReconciler) checkDeploymentStatus(ctx context.Context, deployment *appsv1.Deployment) error {

	if deployment.Status.UpdatedReplicas != *deployment.Spec.Replicas ||
		deployment.Status.ReadyReplicas != *deployment.Spec.Replicas {
		log.Log.Info("Deployment rollout is in progress", "name", deployment.Name, "namespace", deployment.Namespace)
		return fmt.Errorf("rollout in progress")
	}
	kind := "Deployment"

	// Log resource warnings
	if err := r.logResourceWarnings(ctx, deployment.Name, deployment.Namespace, kind); err != nil {
		return fmt.Errorf("failed to log resource warnings for deployment %s/%s: %w", deployment.Namespace, deployment.Name, err)
	}

	log.Log.Info("Deployment health check is complete", "deployment", deployment.Name)
	return nil
}

// Checks rollout status of statefulSet and logs
func (r *RebootPodReconciler) checkStatefulSetStatus(ctx context.Context, statefulSet *appsv1.StatefulSet) error {
	if statefulSet.Status.UpdatedReplicas != *statefulSet.Spec.Replicas ||
		statefulSet.Status.ReadyReplicas != *statefulSet.Spec.Replicas {
		return fmt.Errorf("statefulSet rollout in progress for %s in %s", statefulSet.Name, statefulSet.Namespace)
	}

	kind := "StatefulSet"

	// Log resource warnings
	if err := r.logResourceWarnings(ctx, statefulSet.Name, statefulSet.Namespace, kind); err != nil {
		return fmt.Errorf("failed to log resource warnings for statefulSet %s/%s: %w", statefulSet.Namespace, statefulSet.Name, err)
	}
	log.Log.Info("StatefulSet health check is complete", "statefulSet", statefulSet.Name)
	return nil
}

// func logResourceWarnings is a helper function which finds events related to resource issue
func (r *RebootPodReconciler) logResourceWarnings(ctx context.Context, name string, namespace string, kind string) error {
	log := log.FromContext(ctx)
	var eventList corev1.EventList

	// List events in the namespace to check for warnings
	if err := r.List(ctx, &eventList, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("failed to list events: %w", err)
	}

	for _, event := range eventList.Items {
		if event.Type == corev1.EventTypeWarning && event.InvolvedObject.Name == name && event.InvolvedObject.Kind == kind {
			if strings.Contains(event.Reason, "ResourceQuotaExceeded") || strings.Contains(event.Reason, "LimitRangeExceeded") {
				log.Error(fmt.Errorf("resource limit issue"), "rollout failed due to resource constraints",
					"name", name, "namespace", namespace, "reason", event.Reason)
				return fmt.Errorf("rollout failed due to resource limit issue: %s", event.Reason)
			}
		}
	}
	return nil
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
	ttl, lastRotation, _, _, err := r.fetchTTLFromVault(ctx, name, namespace)
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

// func Start invokes polling and queue-related tasks indepedently
func (r *RebootPodReconciler) Start(ctx context.Context) error {

	// Start the polling loop in a separate goroutine
	go r.StartPollingLoop(ctx)

	// Start worker to process the queue
	go r.startWorker(ctx)

	// startHealthCheckWorker queue performs health check of items in rollout-restart.
	go r.startHealthCheckWorker(ctx)

	<-ctx.Done()       // Block until context is done to keep the reconciler running
	r.Queue.ShutDown() // Gracefully shut down the work queue
	return nil
}

// func startWorker pulls items from the work queue using Queue.Get(), and invokes processQueue.
func (r *RebootPodReconciler) startWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Stop the worker when the context is canceled
			return
		default:
			// Pull an item from the queue, Get() blocks or errors until an obj is received
			obj, shutdown := r.Queue.Get()
			if shutdown {
				return // Exit if the queue is shutting down
			}

			// Process the item
			if err := r.processQueue(ctx, obj); err != nil {
				// Handle errors with rate limiting
				r.Queue.AddRateLimited(obj)
			} else {
				// Successfully processed, clear any retry history
				r.Queue.Forget(obj)
			}

			// Mark item as done in the queue
			r.Queue.Done(obj)
		}
	}
}

// func processQueue calls handleRollout to perform rollout restart
func (r *RebootPodReconciler) processQueue(ctx context.Context, obj interface{}) error {
	// Type assertion to ensure obj is of type types.NamespacedName
	key, ok := obj.(types.NamespacedName)
	if !ok {
		return fmt.Errorf("expected NamespacedName in work queue but got %#v", obj)
	}

	// Perform the rollout restart or check status
	err := r.handleRollout(ctx, key.Name, key.Namespace, ActionRestart)
	if err != nil {
		// Log error and re-enqueue immediately to retry
		log.Log.WithValues("name", key.Name, "namespace", key.Namespace).Error(err, "Failed to perform rollout restart")
		r.Queue.AddRateLimited(key)
		return err
	}

	return nil
}

// picks items from health check queue and calls processHealthCheckQueue to invoke health check
func (r *RebootPodReconciler) startHealthCheckWorker(ctx context.Context) {
	log := log.FromContext(ctx)
	log.Info("Health check worker started")
	for {
		select {
		case <-ctx.Done():
			// Stop the worker gracefully when the context is canceled
			return
		default:
			// Fetch an item from the queue
			obj, shutdown := r.HealthCheckQueue.Get()
			if shutdown {
				log.Info("HealthCheckQueue has been shut down, stopping worker")
				break
			}

			// Use a deferred call to always mark the item as done
			func() {
				defer r.HealthCheckQueue.Done(obj)
				defer func() {
					// Recover from any panic to keep the worker running
					if r := recover(); r != nil {
						log.Error(fmt.Errorf("%v", r), "Panic occurred in health check worker")
					}
				}()

				// Process the queue item
				if err := r.processHealthCheckQueue(ctx, obj); err != nil {
					// Requeue if rollout in progress
					if strings.Contains(err.Error(), "rollout in progress") {
						log.Info("Requeuing workload for further checks", "item", obj)
						r.HealthCheckQueue.AddAfter(obj, time.Minute)
					} else {
						// Log unrecoverable error
						log.Error(err, "Error processing item from HealthCheckQueue", "item", obj)
					}
				}
			}()
		}
	}
}

// calls checkDeploymentStatus or checkStatefulSetStatus for status check after pod reboot
func (r *RebootPodReconciler) processHealthCheckQueue(ctx context.Context, obj interface{}) error {
	log := log.FromContext(ctx)
	namespacedName, ok := obj.(types.NamespacedName)
	if !ok {
		return fmt.Errorf("unexpected type in HealthCheckQueue: %T", obj)
	}

	var rolloutStatus string
	var failedHealthCheck []corev1.ObjectReference

	// Determine the type of workload and fetch the resource accordingly
	var deployment appsv1.Deployment
	if err := r.Get(ctx, namespacedName, &deployment); err == nil {
		log.Info("Checking Deployment status after reboot", "name", deployment.Name, "namespace", deployment.Namespace)
		if err := r.checkDeploymentStatus(ctx, &deployment); err != nil {
			rolloutStatus = "Failure"
			failedHealthCheck = append(failedHealthCheck, corev1.ObjectReference{
				Kind:      "Deployment",
				Name:      deployment.Name,
				Namespace: deployment.Namespace,
			})
		} else {
			rolloutStatus = "Success"
		}
	} else {
		var statefulSet appsv1.StatefulSet
		if err := r.Get(ctx, namespacedName, &statefulSet); err == nil {
			log.Info("Checking StatefulSet status after reboot", "name", statefulSet.Name, "namespace", statefulSet.Namespace)
			if err := r.checkStatefulSetStatus(ctx, &statefulSet); err != nil {
				rolloutStatus = "Failure"
				failedHealthCheck = append(failedHealthCheck, corev1.ObjectReference{
					Kind:      "StatefulSet",
					Name:      statefulSet.Name,
					Namespace: statefulSet.Namespace,
				})
			} else {
				rolloutStatus = "Success"
			}
		} else {
			log.Error(err, "Failed to fetch resource for health check")
			return err
		}
	}

	// Update Status
	if err := r.updateRebootPodStatus(ctx, namespacedName.Namespace, rolloutStatus, failedHealthCheck); err != nil {
		log.Error(err, "Failed to update RebootPod status")
		return err
	}

	// Health check complete; remove from cache and forget from queue
	r.HealthCheckCache.Delete(namespacedName)
	r.HealthCheckQueue.Forget(namespacedName) // Forget this item from the rate-limiting queue
	return nil
}

// updates the status subresource
func (r *RebootPodReconciler) updateRebootPodStatus(ctx context.Context, namespace string, rolloutStatus string, failedHealthCheck []corev1.ObjectReference) error {
	log := log.FromContext(ctx)

	// List all RebootPods in the namespace
	var rebootPods gauravkr19devv1alpha1.RebootPodList
	if err := r.List(ctx, &rebootPods, &client.ListOptions{Namespace: namespace}); err != nil {
		log.Error(err, "Failed to list RebootPods", "namespace", namespace)
		return fmt.Errorf("failed to list RebootPods: %w", err)
	}

	// Iterate over all RebootPods in the namespace and update their status
	for _, rebootPod := range rebootPods.Items {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// Refresh the latest version of the RebootPod, retry logic to address error 'the object has been modified; please apply your changes to the latest version and try again'
			if err := r.Get(ctx, types.NamespacedName{Name: rebootPod.Name, Namespace: rebootPod.Namespace}, &rebootPod); err != nil {
				log.Error(err, "Failed to get latest RebootPod", "namespace", namespace, "name", rebootPod.Name)
				return fmt.Errorf("failed to get latest RebootPod: %w", err)
			}

			// Update Status
			switch rolloutStatus {
			case "Success":
				rebootPod.Status.RolloutStatus.State = "Success"
				rebootPod.Status.RolloutStatus.FailedResources = nil
				rebootPod.Status.RebootCompleted.State = true
				rebootPod.Status.RebootCompleted.FailedHealthChecks = nil
			case "Failure":
				rebootPod.Status.RolloutStatus.State = "Failure"
				rebootPod.Status.RolloutStatus.FailedResources = failedHealthCheck
				rebootPod.Status.RebootCompleted.State = false
				rebootPod.Status.RebootCompleted.FailedHealthChecks = failedHealthCheck
			default: // Pending
				rebootPod.Status.RolloutStatus.State = "Pending"
				rebootPod.Status.RolloutStatus.FailedResources = nil
				rebootPod.Status.RebootCompleted.State = false
				rebootPod.Status.RebootCompleted.FailedHealthChecks = nil
			}

			// Update LastHealthCheck
			rebootPod.Status.LastHealthCheck = metav1.Now()

			// Perform the status update
			return r.Status().Update(ctx, &rebootPod)
		})

		if err != nil {
			log.Error(err, "Failed to update RebootPod status after retries", "namespace", namespace, "name", rebootPod.Name)
			return fmt.Errorf("failed to update RebootPod status for %s: %w", rebootPod.Name, err)
		}

		// Set Prometheus Metric Labels
		rebootCompleted := "false"
		if rebootPod.Status.RebootCompleted.State {
			rebootCompleted = "true"
		}
		failedResources := "None"
		if len(rebootPod.Status.RebootCompleted.FailedHealthChecks) > 0 {
			failedResources = fmt.Sprintf("%d", len(rebootPod.Status.RebootCompleted.FailedHealthChecks))
		}

		// Concatenate all RestartTargets names into a single string
		var restartTargetNames []string
		for _, target := range rebootPod.Spec.RestartTargets {
			restartTargetNames = append(restartTargetNames, target.Name)
		}
		// Join the names with a delimiter (e.g., a comma)
		restartTargetsLabel := strings.Join(restartTargetNames, ", ")

		metrics.HealthCheckVSO.WithLabelValues(
			rebootCompleted,
			rebootPod.Status.RolloutStatus.State,
			failedResources,
			rebootPod.Status.VaultSyncStatus.State,
			rebootPod.Status.VaultSyncStatus.SynchedSecret[0].Name,
			rebootPod.Spec.VaultEndpointDB,
			namespace,
			rebootPod.Name,
			restartTargetsLabel,
		).Set(1)

		log.Info("Successfully updated RebootPod status", "namespace", namespace, "name", rebootPod.Name)
	}
	return nil
}

// Check if the TTL might have expired based on last known rotation and current time
func ttlExpired(lastRotation time.Time) bool {
	// TTL expiry missed by 4s, consider it expired
	expirationBuffer := 4 * time.Second
	now := time.Now()
	// lastRotationExtended := lastRotation.Add(30 * time.Second)
	// Check if the difference between now and the last known rotation time indicates expiration
	return now.Sub(lastRotation) < expirationBuffer
}

// StartPollingLoop continuously checks TTLs in a background goroutine.
func (r *RebootPodReconciler) StartPollingLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Track processed entries to avoid duplicate actions for the same expiry
	processed := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done(): // Stop polling when the context is canceled
			return
		case <-ticker.C: // Execute logic at regular intervals

			for name, entry := range r.Cache { // Iterate over each CR in the cache
				resourceKey := fmt.Sprintf("%s/%s", name, entry.Namespace)

				// First check to validate TTL based on cached data
				if time.Now().After(entry.Expiration) {
					ttl, lastRotation, _, _, err := r.fetchTTLFromVault(ctx, name, entry.Namespace)
					if err != nil {
						log.Log.WithValues("name", name, "namespace", entry.Namespace).Error(err, "Failed to confirm TTL from Vault")
						continue // Skip this iteration if the Vault call fails
					}

					// Second check to validate TTL from Vault before queuing
					if ttl == 0 || ttlExpired(lastRotation) {

						lastProcessed, alreadyProcessed := processed[resourceKey]
						if alreadyProcessed && time.Since(lastProcessed) < 30*time.Second {
							continue
						}

						log.Log.WithValues("name", name, "namespace", entry.Namespace, "ttl", ttl).Info("TTL expired, adding to queue for rollout restart after a minute")

						// Add to workqueue after a short delay to initiate rollout-restart
						r.Queue.AddAfter(types.NamespacedName{Name: name, Namespace: entry.Namespace}, 10*time.Second)

						// Mark as processed with the current timestamp
						processed[resourceKey] = time.Now()
					}
				}
			}
		}
	}
}

// It compares the username/password with the k8s secret
func (r *RebootPodReconciler) vaultSyncStatus(ctx context.Context, rebootPod *gauravkr19devv1alpha1.RebootPod, username, password string) (string, error) {
	log := log.FromContext(ctx)
	var matchingSecretName string
	var secrets corev1.SecretList

	// List all Secrets in the namespace
	if err := r.List(ctx, &secrets, client.InNamespace(rebootPod.Namespace)); err != nil {
		log.Error(err, "Failed to list Secrets in namespace", "namespace", rebootPod.Namespace)
		return "", err
	}

	// Iterate through Secrets to find a match
	for _, secret := range secrets.Items {
		secretUsername := string(secret.Data["username"])
		secretPassword := string(secret.Data["password"])

		if username == secretUsername && password == secretPassword {
			matchingSecretName = secret.Name
			break
		}
	}

	if matchingSecretName == "" {
		log.Info("No matching Secret found for Vault credentials")
		return "", fmt.Errorf("no matching Secret found")
	}

	log.Info("Matching Secret found", "SecretName", matchingSecretName)
	return matchingSecretName, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RebootPodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Start the Work Queue & Polling in a separate goroutine
	go func() {
		if err := r.Start(context.Background()); err != nil {
			log.Log.Error(err, "Failed to start background tasks for RebootPodReconciler")
		}
	}()

	return ctrl.NewControllerManagedBy(mgr).
		For(&gauravkr19devv1alpha1.RebootPod{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}). // Trigger only on creation or update
		Complete(r)
}
