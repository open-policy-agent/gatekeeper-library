---
id: block-wildcard-ingress
title: Block Wildcard Ingress
---

# Block Wildcard Ingress

## Description
Users should not be able to create Ingresses with a blank or wildcard (*) hostname since that would enable them to intercept traffic for other services in the cluster, even if they don't have access to those services.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockwildcardingress
  annotations:
    metadata.gatekeeper.sh/title: "Block Wildcard Ingress"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Users should not be able to create Ingresses with a blank or wildcard (*) hostname since that would enable them to intercept traffic for other services in the cluster, even if they don't have access to those services.
spec:
  crd:
    spec:
      names:
        kind: K8sBlockWildcardIngress
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package K8sBlockWildcardIngress

        contains_wildcard(hostname) = true {
          hostname == ""
        }

        contains_wildcard(hostname) = true {
          contains(hostname, "*")
        }

        violation[{"msg": msg}] {
          input.review.kind.kind == "Ingress"
          # object.get is required to detect omitted host fields
          hostname := object.get(input.review.object.spec.rules[_], "host", "")
          contains_wildcard(hostname)
          msg := sprintf("Hostname '%v' is not allowed since it counts as a wildcard, which can be used to intercept traffic from other applications.", [hostname])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/template.yaml
```
## Examples
<details>
<summary>block-wildcard-ingress</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockWildcardIngress
metadata:
  name: block-wildcard-ingress
spec:
  match:
    kinds:
      - apiGroups: ["extensions", "networking.k8s.io"]
        kinds: ["Ingress"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/samples/block-wildcard-ingress/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: non-wildcard-ingress
spec:
  rules:
  - host: 'myservice.example.com'
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: example
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/samples/block-wildcard-ingress/example_allowed.yaml
```

</details>
<details>
<summary>blank-host</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wildcard-ingress
spec:
  rules:
  - host: ''
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: example
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/samples/block-wildcard-ingress/disallowed/blank_host.yaml
```

</details>
<details>
<summary>host-omitted</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wildcard-ingress
spec:
  rules:
  # Omitted host field counts as a wildcard too
  - http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: example
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/samples/block-wildcard-ingress/disallowed/host_omitted.yaml
```

</details>
<details>
<summary>wildcard-host</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wildcard-ingress
spec:
  rules:
  - host: '*.example.com'
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: example
            port:
              number: 80
  # Extra test to ensure the rule still detects invalid hosts in files containing valid hosts
  - host: 'valid.example.com'
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: example
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/block-wildcard-ingress/samples/block-wildcard-ingress/disallowed/wildcard_host.yaml
```

</details>


</details>