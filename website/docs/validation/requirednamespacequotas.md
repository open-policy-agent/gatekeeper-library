---
id: requirednamespacequotas
title: Required Namespace Quota
---

# Required Namespace Quota

## Description
Ensures that all namespaces have a ResourceQuota defined.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: requirednamespacequota
  annotations:
    metadata.gatekeeper.sh/title: "Required Namespace Quota"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Ensures that all namespaces have a ResourceQuota defined.
spec:
  crd:
    spec:
      names:
        kind: RequiredNamespaceQuota
      validation:
        openAPIV3Schema:
          type: object
          properties:
            message:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package requirednamespacequota

        import rego.v1

        # Enforce that every namespace must have a ResourceQuota
        violation[{"msg": msg}] if {
            input.review.kind.kind == "Namespace"
            ns := input.review.object.metadata.name
            not has_quota
            msg := sprintf("Namespace %v must have a ResourceQuota", [ns])
        }

        # Check if a namespace has a ResourceQuota
        has_quota if {
            some quota in input.review.related
            quota.kind == "ResourceQuota"
            quota.metadata.namespace == input.review.object.metadata.name
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/template.yaml
```
## Examples
<details>
<summary>required-namespace-quota</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredNamespaceQuota
metadata:
  name: enforce-namespace-quota
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  enforcementAction: "warn"
  parameters:
    message: "Every namespace must have a ResourceQuota!"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/samples/constraint.yaml
```

</details>

<details>
<summary>allowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: example-namespace
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: example-quota
  namespace: example-namespace
spec:
  hard:
    pods: "10"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/samples/example_allowed.yaml
```

</details>
<details>
<summary>disallowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: example-namespace-no-quota

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/samples/example_disallowed.yaml
```

</details>
<details>
<summary>update_allowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: example-namespace-updated-with-quota
  labels:
    environment: "production"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: updated-quota
  namespace: example-namespace-updated-with-quota
spec:
  hard:
    pods: "20"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/samples/example_update_allowed.yaml
```

</details>
<details>
<summary>update_disallowed</summary>

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: example-namespace-updated-no-quota
  labels:
    environment: "test"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/requirednamespacequotas/samples/example_update_disallowed.yaml
```

</details>


</details>