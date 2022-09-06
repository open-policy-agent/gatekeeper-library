---
id: httpsonly
title: HTTPS only
---

# HTTPS only

## Description
Requires Ingress resources to be HTTPS only.
Ingress resources must: - include a valid TLS configuration - include the `kubernetes.io/ingress.allow-http` annotation, set to
  `false`.

https://kubernetes.io/docs/concepts/services-networking/ingress/#tls

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8shttpsonly
  annotations:
    metadata.gatekeeper.sh/title: "HTTPS only"
    description: >-
      Requires Ingress resources to be HTTPS only.

      Ingress resources must:
      - include a valid TLS configuration
      - include the `kubernetes.io/ingress.allow-http` annotation, set to
        `false`.

      https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
spec:
  crd:
    spec:
      names:
        kind: K8sHttpsOnly
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8shttpsonly

        violation[{"msg": msg}] {
          input.review.object.kind == "Ingress"
          re_match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)
          ingress := input.review.object
          not https_complete(ingress)
          msg := sprintf("Ingress should be https. tls configuration and allow-http=false annotation are required for %v", [ingress.metadata.name])
        }

        https_complete(ingress) = true {
          ingress.spec["tls"]
          count(ingress.spec.tls) > 0
          ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
        }

```

## Examples
<details>
<summary>block-endpoint-default-role</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sHttpsOnly
metadata:
  name: ingress-https-only
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
  name: ingress-demo-disallowed
  annotations:
    kubernetes.io/ingress.allow-http: "false"
spec:
  tls: [{}]
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
<summary>example-disallowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo-disallowed
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


</blockquote></details>