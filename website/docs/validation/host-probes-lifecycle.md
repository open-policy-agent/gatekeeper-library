---
id: host-probes-lifecycle
title: Host Probes and Lifecycle Hooks
---

# Host Probes and Lifecycle Hooks

## Description
Disallows specifying the host field in probes and lifecycle hooks. The Baseline profile (v1.34+) requires that probes (livenessProbe, readinessProbe, startupProbe) and lifecycle hooks (postStart, preStop) must not specify a host field. This prevents containers from executing network requests to the host node. For more information, see https://kubernetes.io/docs/concepts/security/pod-security-standards/

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spsphostprobeslifecycle
  annotations:
    metadata.gatekeeper.sh/title: "Host Probes and Lifecycle Hooks"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Disallows specifying the host field in probes and lifecycle hooks.
      The Baseline profile (v1.34+) requires that probes (livenessProbe,
      readinessProbe, startupProbe) and lifecycle hooks (postStart, preStop)
      must not specify a host field. This prevents containers from executing
      network requests to the host node.
      For more information, see
      https://kubernetes.io/docs/concepts/security/pod-security-standards/
spec:
  crd:
    spec:
      names:
        kind: K8sPSPHostProbesLifecycle
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Disallows specifying the host field in probes and lifecycle hooks.
            The Baseline profile (v1.34+) requires that probes (livenessProbe,
            readinessProbe, startupProbe) and lifecycle hooks (postStart, preStop)
            must not specify a host field. This prevents containers from executing
            network requests to the host node.
            For more information, see
            https://kubernetes.io/docs/concepts/security/pod-security-standards/
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
      code:
      - engine: K8sNativeValidation
        source:
          variables:
          - name: containers
            expression: 'has(variables.anyObject.spec.containers) ? variables.anyObject.spec.containers : []'
          - name: initContainers
            expression: 'has(variables.anyObject.spec.initContainers) ? variables.anyObject.spec.initContainers : []'
          - name: ephemeralContainers
            expression: 'has(variables.anyObject.spec.ephemeralContainers) ? variables.anyObject.spec.ephemeralContainers : []'
          - name: exemptImagePrefixes
            expression: |
              !has(variables.params.exemptImages) ? [] :
                variables.params.exemptImages.filter(image, image.endsWith("*")).map(image, string(image).replace("*", ""))
          - name: exemptImageExplicit
            expression: |
              !has(variables.params.exemptImages) ? [] : 
                variables.params.exemptImages.filter(image, !image.endsWith("*"))
          - name: exemptImages
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                container.image in variables.exemptImageExplicit ||
                variables.exemptImagePrefixes.exists(exemption, string(container.image).startsWith(exemption))
              ).map(container, container.image)
          - name: allContainers
            expression: 'variables.containers + variables.initContainers + variables.ephemeralContainers'
          - name: badProbeContainers
            expression: |
              variables.allContainers.filter(container,
                !(container.image in variables.exemptImages) &&
                (
                  (has(container.livenessProbe) && has(container.livenessProbe.httpGet) && has(container.livenessProbe.httpGet.host) && container.livenessProbe.httpGet.host != "") ||
                  (has(container.livenessProbe) && has(container.livenessProbe.tcpSocket) && has(container.livenessProbe.tcpSocket.host) && container.livenessProbe.tcpSocket.host != "") ||
                  (has(container.readinessProbe) && has(container.readinessProbe.httpGet) && has(container.readinessProbe.httpGet.host) && container.readinessProbe.httpGet.host != "") ||
                  (has(container.readinessProbe) && has(container.readinessProbe.tcpSocket) && has(container.readinessProbe.tcpSocket.host) && container.readinessProbe.tcpSocket.host != "") ||
                  (has(container.startupProbe) && has(container.startupProbe.httpGet) && has(container.startupProbe.httpGet.host) && container.startupProbe.httpGet.host != "") ||
                  (has(container.startupProbe) && has(container.startupProbe.tcpSocket) && has(container.startupProbe.tcpSocket.host) && container.startupProbe.tcpSocket.host != "")
                )
              ).map(container, "Container " + container.name + " has probe with host field set")
          - name: badLifecycleContainers
            expression: |
              variables.allContainers.filter(container,
                !(container.image in variables.exemptImages) &&
                (
                  (has(container.lifecycle) && has(container.lifecycle.postStart) && has(container.lifecycle.postStart.httpGet) && has(container.lifecycle.postStart.httpGet.host) && container.lifecycle.postStart.httpGet.host != "") ||
                  (has(container.lifecycle) && has(container.lifecycle.postStart) && has(container.lifecycle.postStart.tcpSocket) && has(container.lifecycle.postStart.tcpSocket.host) && container.lifecycle.postStart.tcpSocket.host != "") ||
                  (has(container.lifecycle) && has(container.lifecycle.preStop) && has(container.lifecycle.preStop.httpGet) && has(container.lifecycle.preStop.httpGet.host) && container.lifecycle.preStop.httpGet.host != "") ||
                  (has(container.lifecycle) && has(container.lifecycle.preStop) && has(container.lifecycle.preStop.tcpSocket) && has(container.lifecycle.preStop.tcpSocket.host) && container.lifecycle.preStop.tcpSocket.host != "")
                )
              ).map(container, "Container " + container.name + " has lifecycle hook with host field set")
          - name: isUpdate
            expression: has(request.operation) && request.operation == "UPDATE"
          validations:
          - expression: variables.isUpdate || size(variables.badProbeContainers) == 0
            messageExpression: 'variables.badProbeContainers.join(", ")'
          - expression: variables.isUpdate || size(variables.badLifecycleContainers) == 0
            messageExpression: 'variables.badLifecycleContainers.join(", ")'
      - engine: Rego
        source:
          rego: |
            package k8spsphostprobeslifecycle

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg, "details": {}}] {
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                probe := get_probe(c)
                probe.httpGet.host != ""
                msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.httpGet.host])
            }

            violation[{"msg": msg, "details": {}}] {
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                probe := get_probe(c)
                probe.tcpSocket.host != ""
                msg := sprintf("Container %v has probe with host field set: %v", [c.name, probe.tcpSocket.host])
            }

            violation[{"msg": msg, "details": {}}] {
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                hook := get_lifecycle_hook(c)
                hook.httpGet.host != ""
                msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.httpGet.host])
            }

            violation[{"msg": msg, "details": {}}] {
                not is_update(input.review)

                c := input_containers[_]
                not is_exempt(c)
                hook := get_lifecycle_hook(c)
                hook.tcpSocket.host != ""
                msg := sprintf("Container %v has lifecycle hook with host field set: %v", [c.name, hook.tcpSocket.host])
            }

            get_probe(c) = probe {
                probe := c.livenessProbe
            }

            get_probe(c) = probe {
                probe := c.readinessProbe
            }

            get_probe(c) = probe {
                probe := c.startupProbe
            }

            get_lifecycle_hook(c) = hook {
                hook := c.lifecycle.postStart
            }

            get_lifecycle_hook(c) = hook {
                hook := c.lifecycle.preStop
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
              package lib.exclude_update

              is_update(review) {
                  review.operation == "UPDATE"
              }
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/template.yaml
```
## Examples
<details>
<summary>host-probes-lifecycle-disallowed</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostProbesLifecycle
metadata:
  name: psp-host-probes-lifecycle
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/constraint.yaml
```

</details>

<details>
<summary>example-allowed-no-probes</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-probes-allowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_allowed_no_probes.yaml
```

</details>
<details>
<summary>example-allowed-probe-no-host</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-probe-no-host-allowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    livenessProbe:
      httpGet:
        path: /
        port: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_allowed_probe_no_host.yaml
```

</details>
<details>
<summary>example-disallowed-liveness-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-liveness-probe-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    livenessProbe:
      httpGet:
        path: /
        port: 80
        host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_liveness_probe.yaml
```

</details>
<details>
<summary>example-disallowed-readiness-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-readiness-probe-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    readinessProbe:
      httpGet:
        path: /
        port: 80
        host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_readiness_probe.yaml
```

</details>
<details>
<summary>example-disallowed-startup-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-startup-probe-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    startupProbe:
      httpGet:
        path: /
        port: 80
        host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_startup_probe.yaml
```

</details>
<details>
<summary>example-disallowed-lifecycle-poststart</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-lifecycle-poststart-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    lifecycle:
      postStart:
        httpGet:
          path: /
          port: 80
          host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_lifecycle_poststart.yaml
```

</details>
<details>
<summary>example-disallowed-lifecycle-prestop</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-lifecycle-prestop-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    lifecycle:
      preStop:
        httpGet:
          path: /
          port: 80
          host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_lifecycle_prestop.yaml
```

</details>
<details>
<summary>example-disallowed-tcp-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-tcp-probe-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    livenessProbe:
      tcpSocket:
        port: 80
        host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/example_disallowed_tcp_probe.yaml
```

</details>
<details>
<summary>disallowed-init-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-init-probe-host-disallowed
  labels:
    app: nginx
spec:
  initContainers:
  - name: init
    image: nginx
    livenessProbe:
      httpGet:
        path: /
        port: 80
        host: 127.0.0.1
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/disallowed_init_probe.yaml
```

</details>
<details>
<summary>disallowed-ephemeral-probe</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-ephemeral-probe-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
  ephemeralContainers:
  - name: debug
    image: nginx
    livenessProbe:
      httpGet:
        path: /
        port: 80
        host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/disallowed_ephemeral_probe.yaml
```

</details>
<details>
<summary>disallowed-init-lifecycle</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-init-lifecycle-host-disallowed
  labels:
    app: nginx
spec:
  initContainers:
  - name: init
    image: nginx
    lifecycle:
      postStart:
        httpGet:
          path: /
          port: 80
          host: 127.0.0.1
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/disallowed_init_lifecycle.yaml
```

</details>
<details>
<summary>disallowed-ephemeral-lifecycle</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-ephemeral-lifecycle-host-disallowed
  labels:
    app: nginx
spec:
  containers:
  - name: nginx
    image: nginx
  ephemeralContainers:
  - name: debug
    image: nginx
    lifecycle:
      postStart:
        httpGet:
          path: /
          port: 80
          host: 127.0.0.1

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-probes-lifecycle/samples/psp-host-probes-lifecycle/disallowed_ephemeral_lifecycle.yaml
```

</details>


</details>