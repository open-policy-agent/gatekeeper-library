---
id: replicasknative
title: Knative Replica Limits
---

# Knative Replica Limits

## Description
Requires that knative service objects with the field `annotations.{max,min,initial}Scale` specify a number of replicas within defined ranges.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sknativereplica
  annotations:
    metadata.gatekeeper.sh/title: "Knative Replica Limits"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Requires that knative service objects with the field `annotations.{max,min,initial}Scale` specify a number of replicas within defined ranges.
spec:
  crd:
    spec:
      names:
        kind: K8sKnativeReplica
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            replicas:
              type: integer
              description: Allowed values for numbers of replicas. 
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sknativereplica

        missing(obj, field) = true {
            not obj[field]
        }

        missing(obj, field) = true {
            obj[field] == ""
        }

        violation[{"msg": msg}] {
            service := input.review.object
            missing(service.spec.template.metadata.annotations, "autoscaling.knative.dev/maxScale")
            msg := sprintf("Knative service serving %v has no maxScale value defined", [service.metadata.name])
        }

        violation[{"msg": msg}] {
            service := input.review.object
            missing(service.spec.template.metadata, "annotations")
            msg := sprintf("Knative service serving %v has no annotations defined", [service.metadata.name])
        }

        violation[{"msg": msg}] {
            replicas := input.parameters.replicas
            service := input.review.object
            max_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/maxScale"]
            to_number(replicas) < to_number(max_scale)
            msg := sprintf("maxScale value %v cannot be greater than %v replicas", [max_scale, replicas])
        }

        violation[{"msg": msg}] {
            replicas := input.parameters.replicas
            service := input.review.object
            min_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/minScale"]
            to_number(replicas) < to_number(min_scale)
            msg := sprintf("minScale value %v cannot be greater than %v replicas", [min_scale, replicas])
        }

        violation[{"msg": msg}] {
            replicas := input.parameters.replicas
            service := input.review.object
            max_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/maxScale"]
            min_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/minScale"]
            to_number(max_scale) < to_number(min_scale)
            msg := sprintf("minScale value %v cannot be greater than %v maxScale", [min_scale, max_scale])
        }

        violation[{"msg": msg}] {
            replicas := input.parameters.replicas
            service := input.review.object
            initial_scale := service.spec.template.metadata.annotations["autoscaling.knative.dev/initialScale"]
            to_number(replicas) < to_number(initial_scale)
            msg := sprintf("intialScale value %v cannot be greater than %v replicas", [initial_scale, replicas])
        }
```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicasknative/template.yaml
```
## Examples
<details>
<summary>block-endpoint-default-role</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sKnativeReplica
metadata:
  name: k8sknativereplica
spec:
  match:
    kinds:
      - apiGroups: ["serving.knative.dev"]
        kinds: ["Service"]
  parameters:
    replicas: 10

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicasknative/samples/replicasknative/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: helloworld-go
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "5"
    spec:
      containers:
        - image: gcr.io/knative-samples/helloworld-go

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicasknative/samples/replicasknative/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: helloworld-go
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "8"
        autoscaling.knative.dev/maxScale: "5"
    spec:
      containers:
        - image: gcr.io/knative-samples/helloworld-go
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicasknative/samples/replicasknative/example_disallowed.yaml
```

</details>
<details>
<summary>example-empty-annotations</summary>

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: helloworld-go
spec:
  template:
    metadata:
      creationTimestamp: '2022-12-13T09:21:04Z'
    spec:
      containers:
        - image: gcr.io/knative-samples/helloworld-go
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/replicasknative/samples/replicasknative/example_empty_annotations.yaml
```

</details>


</blockquote></details>