---
id: flexvolume-drivers
title: FlexVolumes
---

# FlexVolumes

## Description
Controls the allowlist of FlexVolume drivers. Corresponds to the `allowedFlexVolumes` field in PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#flexvolume-drivers

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspflexvolumes
  annotations:
    metadata.gatekeeper.sh/title: "FlexVolumes"
    metadata.gatekeeper.sh/version: 1.0.1
    description: >-
      Controls the allowlist of FlexVolume drivers. Corresponds to the
      `allowedFlexVolumes` field in PodSecurityPolicy. For more information,
      see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#flexvolume-drivers
spec:
  crd:
    spec:
      names:
        kind: K8sPSPFlexVolumes
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls the allowlist of FlexVolume drivers. Corresponds to the
            `allowedFlexVolumes` field in PodSecurityPolicy. For more information,
            see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#flexvolume-drivers
          properties:
            allowedFlexVolumes:
              type: array
              description: "An array of AllowedFlexVolume objects."
              items:
                type: object
                properties:
                  driver:
                    description: "The name of the FlexVolume driver."
                    type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspflexvolumes

        import data.lib.exclude_update.is_update

        violation[{"msg": msg, "details": {}}] {
            # spec.volumes field is immutable.
            not is_update(input.review)

            volume := input_flexvolumes[_]
            not input_flexvolumes_allowed(volume)
            msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.review.object.metadata.name, input.parameters.allowedFlexVolumes])
        }

        input_flexvolumes_allowed(volume) {
            input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
        }

        input_flexvolumes[v] {
            v := input.review.object.spec.volumes[_]
            has_field(v, "flexVolume")
        }

        # has_field returns whether an object has a field
        has_field(object, field) = true {
            object[field]
        }
      libs:
        - |
          package lib.exclude_update

          is_update(review) {
              review.operation == "UPDATE"
          }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/flexvolume-drivers/template.yaml
```
## Examples
<details>
<summary>flexvolume-drivers</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPFlexVolumes
metadata:
  name: psp-flexvolume-drivers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedFlexVolumes: #[]
    - driver: "example/lvm"
    - driver: "example/cifs"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/flexvolume-drivers/samples/psp-flexvolume-drivers/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-flexvolume-driver-allowed
  labels:
    app: nginx-flexvolume-driver
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /test
      name: test-volume
      readOnly: true
  volumes:
  - name: test-volume
    flexVolume:
      driver: "example/lvm"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/flexvolume-drivers/samples/psp-flexvolume-drivers/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-flexvolume-driver-disallowed
  labels:
    app: nginx-flexvolume-driver
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /test
      name: test-volume
      readOnly: true
  volumes:
  - name: test-volume
    flexVolume:
      driver: "example/testdriver" #"example/lvm"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/flexvolume-drivers/samples/psp-flexvolume-drivers/example_disallowed.yaml
```

</details>


</details>