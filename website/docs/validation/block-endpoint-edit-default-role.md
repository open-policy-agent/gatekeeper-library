---
id: block-endpoint-edit-default-role
title: Block Endpoint Edit Default Role
---

# Block Endpoint Edit Default Role

## Description
Many Kubernetes installations by default have a system:aggregate-to-edit ClusterRole which does not properly restrict access to editing Endpoints. This ConstraintTemplate forbids the system:aggregate-to-edit ClusterRole from granting permission to create/patch/update Endpoints.
ClusterRole/system:aggregate-to-edit should not allow Endpoint edit permissions due to CVE-2021-25740, Endpoint & EndpointSlice permissions allow cross-Namespace forwarding, https://github.com/kubernetes/kubernetes/issues/103675

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockendpointeditdefaultrole
  annotations:
    metadata.gatekeeper.sh/title: "Block Endpoint Edit Default Role"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Many Kubernetes installations by default have a system:aggregate-to-edit
      ClusterRole which does not properly restrict access to editing Endpoints.
      This ConstraintTemplate forbids the system:aggregate-to-edit ClusterRole
      from granting permission to create/patch/update Endpoints.

      ClusterRole/system:aggregate-to-edit should not allow
      Endpoint edit permissions due to CVE-2021-25740, Endpoint & EndpointSlice
      permissions allow cross-Namespace forwarding,
      https://github.com/kubernetes/kubernetes/issues/103675
spec:
  crd:
    spec:
      names:
        kind: K8sBlockEndpointEditDefaultRole
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockendpointeditdefaultrole

        violation[{"msg": msg}] {
            input.review.object.metadata.name == "system:aggregate-to-edit"
            endpointRule(input.review.object.rules[_])
            msg := "ClusterRole system:aggregate-to-edit should not allow endpoint edit permissions. For k8s version < 1.22, the Cluster Role should be annotated with rbac.authorization.kubernetes.io/autoupdate=false to prevent autoreconciliation back to default permissions for this role."
        }

        endpointRule(rule) {
            "endpoints" == rule.resources[_]
            hasEditVerb(rule.verbs)
        }

        hasEditVerb(verbs) {
            "create" == verbs[_]
        }

        hasEditVerb(verbs) {
            "patch" == verbs[_]
        }

        hasEditVerb(verbs) {
            "update" == verbs[_]
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-endpoint-edit-default-role/template.yaml
```
## Examples
<details>
<summary>block-endpoint-default-role</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockEndpointEditDefaultRole
metadata:
  name: block-endpoint-edit-default-role
spec:
  match:
    kinds:
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["ClusterRole"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-endpoint-edit-default-role/samples/block-endpoint-edit-default-role/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  creationTimestamp: null
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
  name: system:aggregate-to-edit
rules:
- apiGroups:
  - ""
  resources:
  - pods/attach
  - pods/exec
  - pods/portforward
  - pods/proxy
  - secrets
  - services/proxy
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - serviceaccounts
  verbs:
  - impersonate
- apiGroups:
  - ""
  resources:
  - pods
  - pods/attach
  - pods/exec
  - pods/portforward
  - pods/proxy
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - ""
  resources:
  - configmaps
  - persistentvolumeclaims
  - replicationcontrollers
  - replicationcontrollers/scale
  - secrets
  - serviceaccounts
  - services
  - services/proxy
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - apps
  resources:
  - daemonsets
  - deployments
  - deployments/rollback
  - deployments/scale
  - replicasets
  - replicasets/scale
  - statefulsets
  - statefulsets/scale
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - autoscaling
  resources:
  - horizontalpodautoscalers
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - batch
  resources:
  - cronjobs
  - jobs
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - extensions
  resources:
  - daemonsets
  - deployments
  - deployments/rollback
  - deployments/scale
  - ingresses
  - networkpolicies
  - replicasets
  - replicasets/scale
  - replicationcontrollers/scale
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - policy
  resources:
  - poddisruptionbudgets
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  - networkpolicies
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-endpoint-edit-default-role/samples/block-endpoint-edit-default-role/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  creationTimestamp: null
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
  name: system:aggregate-to-edit
rules:
- apiGroups:
  - ""
  resources:
  - pods/attach
  - pods/exec
  - pods/portforward
  - pods/proxy
  - secrets
  - services/proxy
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - serviceaccounts
  verbs:
  - impersonate
- apiGroups:
  - ""
  resources:
  - pods
  - pods/attach
  - pods/exec
  - pods/portforward
  - pods/proxy
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - ""
  resources:
  - configmaps
  - persistentvolumeclaims
  - replicationcontrollers
  - replicationcontrollers/scale
  - secrets
  - serviceaccounts
  - services
  - services/proxy
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update
- apiGroups:
  - apps
  resources:
  - daemonsets
  - deployments
  - deployments/rollback
  - deployments/scale
  - endpoints
  - replicasets
  - replicasets/scale
  - statefulsets
  - statefulsets/scale
  verbs:
  - create
  - delete
  - deletecollection
  - patch
  - update

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-endpoint-edit-default-role/samples/block-endpoint-edit-default-role/example_disallowed.yaml
```

</details>


</details>