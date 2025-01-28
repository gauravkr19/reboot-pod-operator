# rebootpod-controller
The RebootPod controller reboots the pod when TTL of the database password, fetched from Hashicorp Vault, expires. 

## Description
This project is inspired from Hashicorp Vault Secret Operator(VSO) project. VaultDynamicSecret(VDS) a CR from VSO, syncs the database password to k8s Secret and upon password expiry reboots the Pod. Pod reboot is implemented by [_rolloutRestartTargets_](https://developer.hashicorp.com/vault/docs/platform/k8s/vso/api-reference#rolloutrestarttarget). The `rolloutRestartTargets` of VDS is not guaranteed to work with open source vault (as confirmed by Hashicorp Support). This project implements `rolloutRestartTargets` via the CR `RebootPod` which fetches TTL from Vault and reboots the pod listed in the `restartTargets` of the CR. The code also updates .status subresource and Prometheus metrics to monitor `rolloutStatus` and `vaultSyncStatus` of each of the CRs.

# CR
The RebootPod CR
```
apiVersion: gauravkr19.dev/v1alpha1
kind: RebootPod
metadata:
  labels:
    app.kubernetes.io/name: rebootpod-controller
    app.kubernetes.io/managed-by: kustomize
  name: rebootpod-sample
spec:
  vaultEndpointDB: "database/static-creds/dev-postgres"
  jwtRole: "rebootpod-db-postgres"
  restartTargets:
  - kind: Deployment
    name: test-deploy-apps1
  - kind: StatefulSet
    name: test-sts-apps2
status:
  lastHealthCheck: "2025-01-28T07:26:10Z"
  rolloutStatus:
    state: Success
  vaultSyncStatus:
    state: Success
    synchedSecret:
    - name: db-postgres2-secret-apps
      namespace: apps
```
### Authentication with Vault
Operator runs as Deployment and its Pod's service account authenticates via its JWT. `database/static-creds/dev-postgres` this a sensitive endpoint which returns database password along with `ttl` and `last_vault_rotation`, We make use of these fields-  `ttl` and `last_vault_rotation`, to determine the password expiration of the database. We also capture the database password from Vault to compare with the synced K8s secret and expose the status via .status subresource and metrics.

### Releases
* version-1: [Requeue intervals are dynamically adjusted based on TTL value](https://github.com/gauravkr19/reboot-pod-operator/blob/6d405f6d258ec2519ffcf3bd6957a46bb904128a/internal/controller/rebootpod_controller.go)
* version-2: [Used goroutine with waitgroup](https://github.com/gauravkr19/reboot-pod-operator/commit/068b36f96e6b8dee7021fbf13527ffced3b15917)\
Attempted to insert sleep itervals instead of calling Vault API several times. But it missed the TTL expiry of another CR when sleeping on longer intervals. Just used goroutine with waitgroup
* version-3: [Used cache to track the ttl expiration minimizing on controller requeues and call to Vault API](https://github.com/gauravkr19/reboot-pod-operator/commit/4658f8965a75c10cc3d7a371175943ab462c18e8)
* version-4: [Used workqueue, Informer and Prometheus metrics](https://github.com/gauravkr19/reboot-pod-operator/commit/d43d3512248b520f20083fbedec56d9a8133fe10) Introduces workqueues for rollout restart & and for health check. Also, updates .status subresource and Prometheus metrics to monitor `rolloutStatus` and `vaultSyncStatus` of each of the CRs. 

<img width="926" alt="image" src="https://github.com/user-attachments/assets/3a205e22-07dd-4370-9f13-727201394db5" />

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=docker.io/gauravkr19/reboot-pod:v5
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/rebootpod-controller:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/rebootpod-controller:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/rebootpod-controller/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

