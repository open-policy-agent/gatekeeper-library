---
id: block-loadbalancer-services
title: Block Services with type LoadBalancer
---

# Block Services with type LoadBalancer

## Description
Disallows all Services with type LoadBalancer.
https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockloadbalancer
  annotations:
    metadata.gatekeeper.sh/title: "Block Services with type LoadBalancer"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Disallows all Services with type LoadBalancer.

      https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer
spec:
  crd:
    spec:
      names:
        kind: K8sBlockLoadBalancer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockloadbalancer

        violation[{"msg": msg}] {
          input.review.kind.kind == "Service"
          input.review.object.spec.type == "LoadBalancer"
          msg := "User is not allowed to create service of type LoadBalancer"
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/template.yaml
```
## Examples
<details>
<summary>block-loadbalancer-services</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockLoadBalancer
metadata:
  name: block-load-balancer
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Service"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service-allowed
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service-disallowed
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 80
      nodePort: 30007

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-loadbalancer-services/samples/block-load-balancer/example_disallowed.yaml
```

</details>


</details>