---
id: disallowinteractive
title: Disallow Interactive TTY Containers
---

# Disallow Interactive TTY Containers

## Description
Requires that objects have the fields `spec.tty` and `spec.stdin` set to false or unset.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowinteractivetty
  annotations:
    metadata.gatekeeper.sh/title: "Disallow Interactive TTY Containers"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Requires that objects have the fields `spec.tty` and `spec.stdin` set to false or unset.
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowInteractiveTTY
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls use of fields related to gaining an interactive session. Corresponds to the `tty` and
            `stdin` fields in the Pod `spec.containers`, `spec.ephemeralContainers`, and `spec.initContainers`.
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
        package k8sdisallowinteractivetty

        import data.lib.exempt_container.is_exempt

        violation[{"msg": msg, "details": {}}] {
            c := input_containers[_]
            not is_exempt(c)
            input_allow_interactive_fields(c)
            msg := sprintf("Containers using tty or stdin (%v) are not allowed running image: %v", [c.name, c.image])
        }

        input_allow_interactive_fields(c) {
            has_field(c, "stdin")
            not c.stdin == false
        }
        input_allow_interactive_fields(c) {
            has_field(c, "tty")
            not c.tty == false
        }
        input_containers[c] {
            c := input.review.object.spec.containers[_]
        }
        input_containers[c] {
            c := input.review.object.spec.ephemeralContainers[_]
        }
        input_containers[c] {
            c := input.review.object.spec.initContainers[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowinteractive/template.yaml
```
## Examples
<details>
<summary>disallow-interactive</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowInteractiveTTY
metadata:
  name: no-interactive-tty-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowinteractive/samples/no-interactive-containers/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-interactive-tty-allowed
  labels:
    app: nginx-interactive-tty
spec:
  containers:
  - name: nginx
    image: nginx
    stdin: false
    tty: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowinteractive/samples/no-interactive-containers/example_allowed.yaml
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
    stdin: true
    tty: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowinteractive/samples/no-interactive-containers/example_disallowed.yaml
```

</details>


</details>