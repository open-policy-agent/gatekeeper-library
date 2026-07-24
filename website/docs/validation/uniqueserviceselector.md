---
id: uniqueserviceselector
title: Unique Service Selector
---

# Unique Service Selector

## Description
Requires Services to have unique selectors within a namespace. Selectors are considered the same if they have identical keys and values. Selectors may share a key/value pair so long as there is at least one distinct key/value pair between them.
https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8suniqueserviceselector
  annotations:
    metadata.gatekeeper.sh/title: "Unique Service Selector"
    metadata.gatekeeper.sh/version: 1.0.2
    metadata.gatekeeper.sh/requires-sync-data: |
      "[
        [
          {
            "groups":[""],
            "versions": ["v1"],
            "kinds": ["Service"]
          }
        ]
      ]"
    description: >-
      Requires Services to have unique selectors within a namespace.
      Selectors are considered the same if they have identical keys and values.
      Selectors may share a key/value pair so long as there is at least one
      distinct key/value pair between them.

      https://kubernetes.io/docs/concepts/services-networking/service/#defining-a-service
spec:
  crd:
    spec:
      names:
        kind: K8sUniqueServiceSelector
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suniqueserviceselector

        make_apiversion(kind) = apiVersion {
          g := kind.group
          v := kind.version
          g != ""
          apiVersion = sprintf("%v/%v", [g, v])
        }

        make_apiversion(kind) = apiVersion {
          kind.group == ""
          apiVersion = kind.version
        }

        identical(obj, review) {
          obj.metadata.namespace == review.namespace
          obj.metadata.name == review.name
          obj.kind == review.kind.kind
          obj.apiVersion == make_apiversion(review.kind)
        }

        flatten_selector(obj) = flattened {
          selectors := [s | s = concat(":", [key, val]); val = obj.spec.selector[key]]
          flattened := concat(",", sort(selectors))
        }

        violation[{"msg": msg}] {
          input.review.kind.kind == "Service"
          input.review.kind.version == "v1"
          input.review.kind.group == ""
          input_selector := flatten_selector(input.review.object)
          other := data.inventory.namespace[namespace][_]["Service"][name]
          not identical(other, input.review)
          other_selector := flatten_selector(other)
          input_selector == other_selector
          msg := sprintf("same selector as service <%v> in namespace <%v>", [name, namespace])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/template.yaml
```
## Examples
<details>
<summary>unique-service-selector</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sUniqueServiceSelector
metadata:
  name: unique-service-selector
  labels:
    owner: admin.agilebank.demo

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: gatekeeper-test-service-disallowed
  namespace: default
spec:
  ports:
    - port: 443
  selector:
    key: other-value

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: gatekeeper-test-service-disallowed
  namespace: default
spec:
  ports:
    - port: 443
  selector:
    key: value

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueserviceselector/samples/unique-service-selector/example_disallowed.yaml
```

</details>


</details>