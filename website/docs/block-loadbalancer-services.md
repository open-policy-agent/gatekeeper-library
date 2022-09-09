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

## Examples
<details>
<summary>block-loadbalancer-services</summary><blockquote>

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
    excludedNamespaces:
      - "ingress-nginx-private"
      - "ingress-nginx-public"

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

</details>


</blockquote></details>