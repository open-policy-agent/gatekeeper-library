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
          re_match("^(extensions|networking.k8s.io)$", input.review.kind.group)
          host := input.review.object.spec.rules[_].host
          other := data.inventory.namespace[_][otherapiversion]["Ingress"][name]
          re_match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
          other.spec.rules[_].host == host
          not identical(other, input.review)
          msg := sprintf("ingress host conflicts with an existing ingress <%v>", [host])
        }

```

## Examples
<details>
<summary>block-endpoint-default-role</summary><blockquote>

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

</details>


</blockquote></details>