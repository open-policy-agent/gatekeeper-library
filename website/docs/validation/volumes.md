---
id: volumes
title: Volume Types
---

# Volume Types

## Description
Restricts mountable volume types to those specified by the user. Corresponds to the `volumes` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspvolumetypes
  annotations:
    metadata.gatekeeper.sh/title: "Volume Types"
    metadata.gatekeeper.sh/version: 1.0.2
    description: >-
      Restricts mountable volume types to those specified by the user.
      Corresponds to the `volumes` field in a PodSecurityPolicy. For more
      information, see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
spec:
  crd:
    spec:
      names:
        kind: K8sPSPVolumeTypes
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Restricts mountable volume types to those specified by the user.
            Corresponds to the `volumes` field in a PodSecurityPolicy. For more
            information, see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
          properties:
            volumes:
              description: "`volumes` is an array of volume types. All volume types can be enabled using `*`."
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspvolumetypes

        import data.lib.exclude_update.is_update

        violation[{"msg": msg, "details": {}}] {
            # spec.volumes field is immutable.
            not is_update(input.review)

            volume_fields := {x | input.review.object.spec.volumes[_][x]; x != "name"}
            field := volume_fields[_]
            not input_volume_type_allowed(field)
            msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.review.object.metadata.name, input.parameters.volumes])
        }

        # * may be used to allow all volume types
        input_volume_type_allowed(_) {
            input.parameters.volumes[_] == "*"
        }

        input_volume_type_allowed(field) {
            field == input.parameters.volumes[_]
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/volumes/template.yaml
```
## Examples
<details>
<summary>host-path-disallowed</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPVolumeTypes
metadata:
  name: psp-volume-types
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    volumes:
    # - "*" # * may be used to allow all volume types
    - configMap
    - emptyDir
    - projected
    - secret
    - downwardAPI
    - persistentVolumeClaim
    #- hostPath #required for allowedHostPaths
    - flexVolume #required for allowedFlexVolumes

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/volumes/samples/psp-volume-types/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-volume-types-disallowed
  labels:
    app: nginx-volume-types
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /cache
      name: cache-volume
  - name: nginx2
    image: nginx
    volumeMounts:
    - mountPath: /cache2
      name: demo-vol
  volumes:
  - name: cache-volume
    hostPath:
      path: /tmp # directory location on host
  - name: demo-vol
    emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/volumes/samples/psp-volume-types/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-volume-types-allowed
  labels:
    app: nginx-volume-types
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /cache
      name: cache-volume
  - name: nginx2
    image: nginx
    volumeMounts:
    - mountPath: /cache2
      name: demo-vol
  volumes:
  - name: cache-volume
    emptyDir: {}
  - name: demo-vol
    emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/volumes/samples/psp-volume-types/example_allowed.yaml
```

</details>


</details>