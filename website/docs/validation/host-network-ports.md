---
id: host-network-ports
title: Host Networking Ports
---

# Host Networking Ports

## Description
Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific ports must be specified. Corresponds to the `hostNetwork` and `hostPorts` fields in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spsphostnetworkingports
  annotations:
    metadata.gatekeeper.sh/title: "Host Networking Ports"
    metadata.gatekeeper.sh/version: 1.1.4
    description: >-
      Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific
      ports must be specified. Corresponds to the `hostNetwork` and
      `hostPorts` fields in a PodSecurityPolicy. For more information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
spec:
  crd:
    spec:
      names:
        kind: K8sPSPHostNetworkingPorts
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls usage of host network namespace by pod containers. HostNetwork verification happens without exception for exemptImages. Specific
            ports must be specified. Corresponds to the `hostNetwork` and
            `hostPorts` fields in a PodSecurityPolicy. For more information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#host-namespaces
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
            hostNetwork:
              description: "Determines if the policy allows the use of HostNetwork in the pod spec."
              type: boolean
            min:
              description: "The start of the allowed port range, inclusive."
              type: integer
            max:
              description: "The end of the allowed port range, inclusive."
              type: integer
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
          - name: badContainers
            expression: |
              (variables.containers + variables.initContainers + variables.ephemeralContainers).filter(container,
                !(container.image in variables.exemptImages) && has(container.ports) &&
                (
                  (container.ports.all(port, has(port.hostPort) && has(variables.params.min) && port.hostPort < variables.params.min)) ||
                  (container.ports.all(port, has(port.hostPort) && has(variables.params.max) && port.hostPort > variables.params.max))
                )
              )
          - name: isUpdate
            expression: has(request.operation) && request.operation == "UPDATE"
          - name: hostNetworkAllowed
            expression: has(variables.params.hostNetwork) && variables.params.hostNetwork
          - name: hostNetworkEnabled
            expression: has(variables.anyObject.spec.hostNetwork) && variables.anyObject.spec.hostNetwork
          - name: hostNetworkViolation
            expression: variables.hostNetworkEnabled && !variables.hostNetworkAllowed
          validations:
          - expression: 'variables.isUpdate || size(variables.badContainers) == 0'
            messageExpression: '"The specified hostNetwork and hostPort are not allowed, pod: " + variables.anyObject.metadata.name'
          - expression: variables.isUpdate || !variables.hostNetworkViolation
            messageExpression: '"The specified hostNetwork and hostPort are not allowed, pod: " + variables.anyObject.metadata.name'
      - engine: Rego
        source:
          rego: |
            package k8spsphostnetworkingports

            import data.lib.exclude_update.is_update
            import data.lib.exempt_container.is_exempt

            violation[{"msg": msg, "details": {}}] {
                # spec.hostNetwork field is immutable.
                not is_update(input.review)

                input_share_hostnetwork(input.review.object)
                msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.review.object.metadata.name, input.parameters])
            }

            input_share_hostnetwork(o) {
                not input.parameters.hostNetwork
                o.spec.hostNetwork
            }

            input_share_hostnetwork(_) {
                hostPort := input_containers[_].ports[_].hostPort
                hostPort < input.parameters.min
            }

            input_share_hostnetwork(_) {
                hostPort := input_containers[_].ports[_].hostPort
                hostPort > input.parameters.max
            }

            input_containers[c] {
                c := input.review.object.spec.containers[_]
                not is_exempt(c)
            }

            input_containers[c] {
                c := input.review.object.spec.initContainers[_]
                not is_exempt(c)
            }

            input_containers[c] {
                c := input.review.object.spec.ephemeralContainers[_]
                not is_exempt(c)
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/template.yaml
```
## Examples
<details>
<summary>port-range-with-host-network-allowed</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNetworkingPorts
metadata:
  name: psp-host-network-ports
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    hostNetwork: true
    min: 80
    max: 9000
    exemptImages:
    - "safeimages.com/*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/constraint.yaml
```

</details>

<details>
<summary>out-of-range</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-disallowed
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/example_disallowed_out_of_range_host_network_true.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-allowed
  labels:
    app: nginx-host-networking-ports
spec:
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9000
      hostPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_in_range.yaml
```

</details>
<details>
<summary>out-of-range-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-disallowed
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  ephemeralContainers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/disallowed_ephemeral.yaml
```

</details>
<details>
<summary>no-ports-specified</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-disallowed
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports.yaml
```

</details>
<details>
<summary>port-violation-exempted</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-exempted
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: safeimages.com/nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_out_of_range_exempted.yaml
```

</details>


</details><details>
<summary>host-network-forbidden</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNetworkingPorts
metadata:
  name: psp-host-network
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    hostNetwork: false

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/block_host_network/constraint.yaml
```

</details>

<details>
<summary>hostnetwork-true</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-network-true
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports_host_network_true.yaml
```

</details>
<details>
<summary>hostnetwork-false</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-network-false
spec:
  hostNetwork: false
  containers:
  - name: nginx
    image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_no_ports_host_network_false.yaml
```

</details>


</details><details>
<summary>port-range-with-host-network-forbidden</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostNetworkingPorts
metadata:
  name: psp-host-network-ports
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    hostNetwork: false
    min: 80
    max: 9000
    exemptImages:
    - "safeimages.com/*"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/constraint.yaml
```

</details>

<details>
<summary>out-of-range-and-host-network-true</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-disallowed
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/example_disallowed_out_of_range_host_network_true.yaml
```

</details>
<details>
<summary>exempted-image-still-violates-on-hostnetwork</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-hn-ok-bad-port
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: safeimages.com/nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/port_range_block_host_network/example_disallowed_exempted_container_host_network_enabled.yaml
```

</details>
<details>
<summary>in-range-host-network-false</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-allowed
  labels:
    app: nginx-host-networking-ports
spec:
  containers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9000
      hostPort: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/example_allowed_in_range.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-networking-ports-disallowed
  labels:
    app: nginx-host-networking-ports
spec:
  hostNetwork: true
  ephemeralContainers:
  - name: nginx
    image: nginx
    ports:
    - containerPort: 9001
      hostPort: 9001

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-network-ports/samples/psp-host-network-ports/disallowed_ephemeral.yaml
```

</details>


</details>