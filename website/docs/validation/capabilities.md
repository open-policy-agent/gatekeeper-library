---
id: capabilities
title: Capabilities
---

# Capabilities

## Description
Controls Linux capabilities on containers. Corresponds to the `allowedCapabilities` and `requiredDropCapabilities` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspcapabilities
  annotations:
    metadata.gatekeeper.sh/title: "Capabilities"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Controls Linux capabilities on containers. Corresponds to the
      `allowedCapabilities` and `requiredDropCapabilities` fields in a
      PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities
spec:
  crd:
    spec:
      names:
        kind: K8sPSPCapabilities
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls Linux capabilities on containers. Corresponds to the
            `allowedCapabilities` and `requiredDropCapabilities` fields in a
            PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#capabilities
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
            allowedCapabilities:
              type: array
              description: "A list of Linux capabilities that can be added to a container."
              items:
                type: string
            requiredDropCapabilities:
              type: array
              description: "A list of Linux capabilities that are required to be dropped from a container."
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package capabilities

        import data.lib.exempt_container.is_exempt

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not is_exempt(container)
          has_disallowed_capabilities(container)
          msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not is_exempt(container)
          missing_drop_capabilities(container)
          msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
        }



        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not is_exempt(container)
          has_disallowed_capabilities(container)
          msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not is_exempt(container)
          missing_drop_capabilities(container)
          msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
        }



        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          not is_exempt(container)
          has_disallowed_capabilities(container)
          msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.ephemeralContainers[_]
          not is_exempt(container)
          missing_drop_capabilities(container)
          msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
        }


        has_disallowed_capabilities(container) {
          allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
          not allowed["*"]
          capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

          count(capabilities - allowed) > 0
        }

        missing_drop_capabilities(container) {
          must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
          all := {"all"}
          dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

          count(must_drop - dropped) > 0
          count(all - dropped) > 0
        }

        get_default(obj, param, _default) = out {
          out = obj[param]
        }

        get_default(obj, param, _default) = out {
          not obj[param]
          not obj[param] == false
          out = _default
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/template.yaml
```
## Examples
<details>
<summary>capabilities</summary><blockquote>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPCapabilities
metadata:
  name: capabilities-demo
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "default"
  parameters:
    allowedCapabilities: ["something"]
    requiredDropCapabilities: ["must_drop"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      securityContext:
        capabilities:
          add: ["disallowedcapability"]
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"
```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-allowed
  labels:
    owner: me.agilebank.demo
spec:
  containers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      securityContext:
        capabilities:
          add: ["something"]
          drop: ["must_drop", "another_one"]
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: opa-disallowed
  labels:
    owner: me.agilebank.demo
spec:
  ephemeralContainers:
    - name: opa
      image: openpolicyagent/opa:0.9.2
      args:
        - "run"
        - "--server"
        - "--addr=localhost:8080"
      securityContext:
        capabilities:
          add: ["disallowedcapability"]
      resources:
        limits:
          cpu: "100m"
          memory: "30Mi"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/capabilities/samples/capabilities-demo/disallowed_ephemeral.yaml
```

</details>


</blockquote></details>