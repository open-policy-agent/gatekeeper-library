---
id: allow-privilege-escalation
title: Allow Privilege Escalation in Container
---

# Allow Privilege Escalation in Container

## Description
Controls restricting escalation to root privileges. Corresponds to the `allowPrivilegeEscalation` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspallowprivilegeescalationcontainer
  annotations:
    metadata.gatekeeper.sh/title: "Allow Privilege Escalation in Container"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Controls restricting escalation to root privileges. Corresponds to the
      `allowPrivilegeEscalation` field in a PodSecurityPolicy. For more
      information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation
spec:
  crd:
    spec:
      names:
        kind: K8sPSPAllowPrivilegeEscalationContainer
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Controls restricting escalation to root privileges. Corresponds to the
            `allowPrivilegeEscalation` field in a PodSecurityPolicy. For more
            information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation
          properties:
            exemptImages:
              description: >-
                Any container that uses an image that matches an entry in this list will be excluded
                from enforcement. Prefix-matching can be signified with `*`. For example: `my-image-*`.

                It is recommended that users use the fully-qualified Docker image name (e.g. start with a domain name)
                in order to avoid unexpectedly exempting images from an untrusted repository.
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspallowprivilegeescalationcontainer

        import data.lib.exempt_container.is_exempt

        violation[{"msg": msg, "details": {}}] {
            c := input_containers[_]
            not is_exempt(c)
            input_allow_privilege_escalation(c)
            msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
        }

        input_allow_privilege_escalation(c) {
            not has_field(c, "securityContext")
        }
        input_allow_privilege_escalation(c) {
            not c.securityContext.allowPrivilegeEscalation == false
        }
        input_containers[c] {
            c := input.review.object.spec.containers[_]
        }
        input_containers[c] {
            c := input.review.object.spec.initContainers[_]
        }
        input_containers[c] {
            c := input.review.object.spec.ephemeralContainers[_]
        }
        # has_field returns whether an object has a field
        has_field(object, field) = true {
            object[field]
        }
      libs:
        - |
          package lib.exempt_container

          is_exempt(container) {
              exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
              img := container.image
              exemption := exempt_images[_]
              _matches_exemption(img, exemption)
          }

          _matches_exemption(img, exemption) {
              not endswith(exemption, "*")
              exemption == img
          }

          _matches_exemption(img, exemption) {
              endswith(exemption, "*")
              prefix := trim_suffix(exemption, "*")
              startswith(img, prefix)
          }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/allow-privilege-escalation/template.yaml
```
## Examples
<details>
<summary>allow-privilege-escalation</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPAllowPrivilegeEscalationContainer
metadata:
  name: psp-allow-privilege-escalation-container
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/allow-privilege-escalation/samples/psp-allow-privilege-escalation-container/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-privilege-escalation-allowed
  labels:
    app: nginx-privilege-escalation
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/allow-privilege-escalation/samples/psp-allow-privilege-escalation-container/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-privilege-escalation-disallowed
  labels:
    app: nginx-privilege-escalation
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/allow-privilege-escalation/samples/psp-allow-privilege-escalation-container/example_disallowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-privilege-escalation-disallowed
  labels:
    app: nginx-privilege-escalation
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/allow-privilege-escalation/samples/psp-allow-privilege-escalation-container/disallowed_ephemeral.yaml
```

</details>


</blockquote></details>