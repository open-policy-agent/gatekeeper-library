---
id: httpsonly
title: HTTPS Only
---

# HTTPS Only

## Description
Requires Ingress resources to be HTTPS only.  Ingress resources must include the `kubernetes.io/ingress.allow-http` annotation, set to `false`. By default a valid TLS {} configuration is required, this can be made optional by setting the `tlsOptional` parameter to `true`.
https://kubernetes.io/docs/concepts/services-networking/ingress/#tls

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8shttpsonly
  annotations:
    metadata.gatekeeper.sh/title: "HTTPS Only"
    metadata.gatekeeper.sh/version: 1.0.2
    description: >-
      Requires Ingress resources to be HTTPS only.  Ingress resources must
      include the `kubernetes.io/ingress.allow-http` annotation, set to `false`.
      By default a valid TLS {} configuration is required, this can be made
      optional by setting the `tlsOptional` parameter to `true`.

      https://kubernetes.io/docs/concepts/services-networking/ingress/#tls
spec:
  crd:
    spec:
      names:
        kind: K8sHttpsOnly
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Requires Ingress resources to be HTTPS only.  Ingress resources must
            include the `kubernetes.io/ingress.allow-http` annotation, set to
            `false`. By default a valid TLS {} configuration is required, this
            can be made optional by setting the `tlsOptional` parameter to
            `true`.
          properties:
            tlsOptional:
              type: boolean
              description: "When set to `true` the TLS {} is optional, defaults
              to false."
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8shttpsonly

        violation[{"msg": msg}] {
          input.review.object.kind == "Ingress"
          regex.match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)
          ingress := input.review.object
          not https_complete(ingress)
          not tls_is_optional
          msg := sprintf("Ingress should be https. tls configuration and allow-http=false annotation are required for %v", [ingress.metadata.name])
        }

        violation[{"msg": msg}] {
          input.review.object.kind == "Ingress"
          regex.match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)
          ingress := input.review.object
          not annotation_complete(ingress)
          tls_is_optional
          msg := sprintf("Ingress should be https. The allow-http=false annotation is required for %v", [ingress.metadata.name])
        }

        https_complete(ingress) = true {
          ingress.spec["tls"]
          count(ingress.spec.tls) > 0
          ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
        }

        annotation_complete(ingress) = true {
          ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
        }

        tls_is_optional {
          parameters := object.get(input, "parameters", {})
          object.get(parameters, "tlsOptional", false) == true
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/template.yaml
```
## Examples
<details>
<summary>tls-required</summary>

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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo-allowed
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/example_allowed.yaml
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

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only/example_disallowed.yaml
```

</details>


</details><details>
<summary>tls-optional</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sHttpsOnly
metadata:
  name: ingress-https-only-tls-optional
spec:
  match:
    kinds:
      - apiGroups: ["extensions", "networking.k8s.io"]
        kinds: ["Ingress"]
  parameters:
    tlsOptional: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/constraint.yaml
```

</details>

<details>
<summary>example-allowed-tls-optional</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo-allowed-tls-optional
  annotations:
    kubernetes.io/ingress.allow-http: "false"
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed-tls-optional</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo-disallowed-tls-optional
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/httpsonly/samples/ingress-https-only-tls-optional/example_disallowed.yaml
```

</details>


</details>