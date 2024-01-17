---
id: disallowedtags
title: Disallow tags
---

# Disallow tags

## Description
Requires container images to have an image tag different from the ones in the specified list.
https://kubernetes.io/docs/concepts/containers/images/#image-names

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowedtags
  annotations:
    metadata.gatekeeper.sh/title: "Disallow tags"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Requires container images to have an image tag different from the ones in
      the specified list.

      https://kubernetes.io/docs/concepts/containers/images/#image-names
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowedTags
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
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
            tags:
              type: array
              description: Disallowed container image tags.
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowedtags

        import data.lib.exempt_container.is_exempt

        violation[{"msg": msg}] {
            container := input_containers[_]
            not is_exempt(container)
            tags := [tag_with_prefix | tag := input.parameters.tags[_]; tag_with_prefix := concat(":", ["", tag])]
            strings.any_suffix_match(container.image, tags)
            msg := sprintf("container <%v> uses a disallowed tag <%v>; disallowed tags are %v", [container.name, container.image, input.parameters.tags])
        }

        violation[{"msg": msg}] {
            container := input_containers[_]
            not is_exempt(container)
            not contains(container.image, ":")
            msg := sprintf("container <%v> didn't specify an image tag <%v>", [container.name, container.image])
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/template.yaml
```
## Examples
<details>
<summary>disallowed-tags</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowedTags
metadata:
  name: container-image-must-not-have-latest-tag
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "default"
  parameters:
    tags: ["latest"]
    exemptImages: ["openpolicyagent/opa-exp:latest", "openpolicyagent/opa-exp2:latest"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/constraint.yaml
```

</details>

<details>
<summary>allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/example_allowed.yaml
```

</details>
<details>
<summary>exempt-images-with-disallowed-tags</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-exempt-allowed
spec:
  containers:
    - name: opa-exp
      image: openpolicyagent/opa-exp:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
    - name: opa-init
      image: openpolicyagent/init:v1
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
    - name: opa-exp2
      image: openpolicyagent/opa-exp2:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/example_exempt_image_w_disallowed_tag.yaml
```

</details>
<details>
<summary>no-tag</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/example_no_tag.yaml
```

</details>
<details>
<summary>single-disallowed-tag</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed-2
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/example_disallowed_tag.yaml
```

</details>
<details>
<summary>single-disallowed-tag-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed-ephemeral
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
  ephemeralContainers:
    - name: opa
      image: openpolicyagent/opa:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/disallowed_tag_ephemeral.yaml
```

</details>
<details>
<summary>some-disallow-tags</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed-3
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa-exp:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
    - name: opa-init
      image: openpolicyagent/init:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
    - name: opa-exp2
      image: openpolicyagent/opa-exp2:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
    - name: opa-monitor
      image: openpolicyagent/monitor:latest
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/disallowedtags/samples/container-image-must-not-have-latest-tag/example_some_disallowed_tags.yaml
```

</details>


</details>