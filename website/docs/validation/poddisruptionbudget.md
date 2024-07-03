---
id: poddisruptionbudget
title: Pod Disruption Budget
---

# Pod Disruption Budget

## Description
Disallow the following scenarios when deploying PodDisruptionBudgets or resources that implement the replica subresource (e.g. Deployment, ReplicationController, ReplicaSet, StatefulSet): 1. Deployment of PodDisruptionBudgets with .spec.maxUnavailable == 0 2. Deployment of PodDisruptionBudgets with .spec.minAvailable == .spec.replicas of the resource with replica subresource This will prevent PodDisruptionBudgets from blocking voluntary disruptions such as node draining.
https://kubernetes.io/docs/concepts/workloads/pods/disruptions/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spoddisruptionbudget
  annotations:
    metadata.gatekeeper.sh/title: "Pod Disruption Budget"
    metadata.gatekeeper.sh/version: 1.0.4
    metadata.gatekeeper.sh/requires-sync-data: |
      "[
        [
          {
            "groups":["policy"],
            "versions": ["v1"],
            "kinds": ["PodDisruptionBudget"]
          }
        ]
      ]"
    description: >-
      Disallow the following scenarios when deploying PodDisruptionBudgets or resources that implement the replica subresource (e.g. Deployment, ReplicationController, ReplicaSet, StatefulSet):
      1. Deployment of PodDisruptionBudgets with .spec.maxUnavailable == 0
      2. Deployment of PodDisruptionBudgets with .spec.minAvailable == .spec.replicas of the resource with replica subresource
      This will prevent PodDisruptionBudgets from blocking voluntary disruptions such as node draining.

      https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
spec:
  crd:
    spec:
      names:
        kind: K8sPodDisruptionBudget
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spoddisruptionbudget

        violation[{"msg": msg}] {
          input.review.kind.kind == "PodDisruptionBudget"
          pdb := input.review.object

          not valid_pdb_max_unavailable(pdb)
          msg := sprintf(
            "PodDisruptionBudget <%v> has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
            [pdb.metadata.name],
          )
        }

        violation[{"msg": msg}] {
          obj := input.review.object
          pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]

          matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
          labels := { [label, value] | some label; value := obj.spec.selector.matchLabels[label] }
          count(matchLabels - labels) == 0

          not valid_pdb_max_unavailable(pdb)
          msg := sprintf(
            "%v <%v> has been selected by PodDisruptionBudget <%v> but has maxUnavailable of 0, only positive integers are allowed for maxUnavailable",
            [obj.kind, obj.metadata.name, pdb.metadata.name],
          )
        }

        violation[{"msg": msg}] {
          obj := input.review.object
          pdb := data.inventory.namespace[obj.metadata.namespace]["policy/v1"].PodDisruptionBudget[_]
          
          matchLabels := { [label, value] | some label; value := pdb.spec.selector.matchLabels[label] }
          labels := { [label, value] | some label; value := obj.spec.selector.matchLabels[label] }
          count(matchLabels - labels) == 0

          not valid_pdb_min_available(obj, pdb)
          msg := sprintf(
            "%v <%v> has %v replica(s) but PodDisruptionBudget <%v> has minAvailable of %v, PodDisruptionBudget count should always be lower than replica(s), and not used when replica(s) is set to 1",
            [obj.kind, obj.metadata.name, obj.spec.replicas, pdb.metadata.name, pdb.spec.minAvailable],
          )
        }

        valid_pdb_min_available(obj, pdb) {
          # default to -1 if minAvailable is not set so valid_pdb_min_available is always true
          # for objects with >= 0 replicas. If minAvailable defaults to >= 0, objects with
          # replicas field might violate this constraint if they are equal to the default set here
          min_available := object.get(pdb.spec, "minAvailable", -1)
          obj.spec.replicas > min_available
        }

        valid_pdb_max_unavailable(pdb) {
          # default to 1 if maxUnavailable is not set so valid_pdb_max_unavailable always returns true.
          # If maxUnavailable defaults to 0, it violates this constraint because all pods needs to be
          # available and no pods can be evicted voluntarily
          max_unavailable := object.get(pdb.spec, "maxUnavailable", 1)
          max_unavailable > 0
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/template.yaml
```
## Examples
<details>
<summary>pod-disruption-budget</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPodDisruptionBudget
metadata:
  name: pod-distruption-budget
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet"]
      - apiGroups: ["policy"]
        kinds: ["PodDisruptionBudget"]
      - apiGroups: [""]
        kinds: ["ReplicationController"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/constraint.yaml
```

</details>

<details>
<summary>example-allowed-pdb</summary>

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb-allowed
  namespace: default
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      foo: bar

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_allowed_pdb.yaml
```

</details>
<details>
<summary>example-disallowed-pdb</summary>

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb-disallowed
  namespace: default
spec:
  maxUnavailable: 0
  selector:
    matchLabels:
      foo: bar

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_disallowed_pdb.yaml
```

</details>
<details>
<summary>example-allowed-min-available</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-allowed-1
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
      example: allowed-deployment-1
  template:
    metadata:
      labels:
        app: nginx
        example: allowed-deployment-1
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_allowed_deployment1.yaml
```

</details>
<details>
<summary>example-allowed-max-unavailable</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-allowed-2
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
      example: allowed-deployment-2
  template:
    metadata:
      labels:
        app: nginx
        example: allowed-deployment-2
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_allowed_deployment2.yaml
```

</details>
<details>
<summary>example-allowed-subset-selector</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-allowed-3
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
      example: allowed-deployment-3
  template:
    metadata:
      labels:
        app: nginx
        example: allowed-deployment-3
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_allowed_deployment3.yaml
```

</details>
<details>
<summary>example-allowed-nomatch-selector</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-allowed-4
  namespace: default
  labels:
    app: non-matching-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: non-matching-nginx
      example: allowed-deployment-4
  template:
    metadata:
      labels:
        app: non-matching-nginx
        example: allowed-deployment-4
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_allowed_deployment4.yaml
```

</details>
<details>
<summary>example-disallowed-min-available</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-disallowed
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
      example: disallowed-deployment
  template:
    metadata:
      labels:
        app: nginx
        example: disallowed-deployment
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/poddisruptionbudget/samples/poddisruptionbudget/example_disallowed_deployment.yaml
```

</details>


</details>