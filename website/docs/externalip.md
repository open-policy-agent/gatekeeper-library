---
id: externalip
title: External IPs
---

# External IPs

## Description
Restricts Service externalIPs to an allowed list of IP addresses.
https://kubernetes.io/docs/concepts/services-networking/service/#external-ips

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sexternalips
  annotations:
    metadata.gatekeeper.sh/title: "External IPs"
    description: >-
      Restricts Service externalIPs to an allowed list of IP addresses.

      https://kubernetes.io/docs/concepts/services-networking/service/#external-ips
spec:
  crd:
    spec:
      names:
        kind: K8sExternalIPs
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            allowedIPs:
              type: array
              description: "An allow-list of external IP addresses."
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sexternalips

        violation[{"msg": msg}] {
          input.review.kind.kind == "Service"
          input.review.kind.group == ""
          allowedIPs := {ip | ip := input.parameters.allowedIPs[_]}
          externalIPs := {ip | ip := input.review.object.spec.externalIPs[_]}
          forbiddenIPs := externalIPs - allowedIPs
          count(forbiddenIPs) > 0
          msg := sprintf("service has forbidden external IPs: %v", [forbiddenIPs])
        }

```

## Examples
<details>
<summary>block-endpoint-default-role</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sExternalIPs
metadata:
  name: external-ips
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Service"]
  parameters:
    allowedIPs:
      - "203.0.113.0"

```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: allowed-external-ip
spec:
  selector:
    app: MyApp
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
  externalIPs:
    - 203.0.113.0

```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Service
metadata:
  name: disallowed-external-ip
spec:
  selector:
    app: MyApp
  ports:
  - name: http
    protocol: TCP
    port: 80
    targetPort: 8080
  externalIPs:
    - 1.1.1.1

```

</details>


</blockquote></details>