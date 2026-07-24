---
id: uniqueingresshost
title: Unique Ingress Host
---

# Unique Ingress Host

## Description
Requires all Ingress rule hosts to be unique.
Does not handle hostname wildcards: https://kubernetes.io/docs/concepts/services-networking/ingress/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8suniqueingresshost
  annotations:
    metadata.gatekeeper.sh/title: "Unique Ingress Host"
    metadata.gatekeeper.sh/version: 1.0.4
    metadata.gatekeeper.sh/requires-sync-data: |
      "[
        [
          {
            "groups": ["extensions"],
            "versions": ["v1beta1"],
            "kinds": ["Ingress"]
          },
          {
            "groups": ["networking.k8s.io"],
            "versions": ["v1beta1", "v1"],
            "kinds": ["Ingress"]
          }
        ]
      ]"
    description: >-
      Requires all Ingress rule hosts to be unique.

      Does not handle hostname wildcards:
      https://kubernetes.io/docs/concepts/services-networking/ingress/
spec:
  crd:
    spec:
      names:
        kind: K8sUniqueIngressHost
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suniqueingresshost

        identical(obj, review) {
          obj.metadata.namespace == review.object.metadata.namespace
          obj.metadata.name == review.object.metadata.name
        }

        violation[{"msg": msg}] {
          input.review.kind.kind == "Ingress"
          regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
          host := input.review.object.spec.rules[_].host
          other := data.inventory.namespace[_][otherapiversion]["Ingress"][name]
          regex.match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
          other.spec.rules[_].host == host
          not identical(other, input.review)
          msg := sprintf("ingress host conflicts with an existing ingress <%v>", [host])
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/template.yaml
```
## Examples
<details>
<summary>unique-ingress-host</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sUniqueIngressHost
metadata:
  name: unique-ingress-host
spec:
  match:
    kinds:
      - apiGroups: ["extensions", "networking.k8s.io"]
        kinds: ["Ingress"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-host-allowed
  namespace: default
spec:
  rules:
  - host: example-allowed-host.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: nginx
            port:
              number: 80
  - host: example-allowed-host1.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: nginx2
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-host-disallowed
  namespace: default
spec:
  rules:
  - host: example-host.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: nginx
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_disallowed.yaml
```

</details>
<details>
<summary>example-disallowed2</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-host-disallowed2
  namespace: default
spec:
  rules:
  - host: example-host2.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: nginx
            port:
              number: 80
  - host: example-host3.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: nginx2
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/uniqueingresshost/samples/unique-ingress-host/example_disallowed2.yaml
```

</details>


</details>