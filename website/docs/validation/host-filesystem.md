---
id: host-filesystem
title: Host Filesystem
---

# Host Filesystem

## Description
Controls usage of the host filesystem. Corresponds to the `allowedHostPaths` field in a PodSecurityPolicy. For more information, see https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spsphostfilesystem
  annotations:
    metadata.gatekeeper.sh/title: "Host Filesystem"
    metadata.gatekeeper.sh/version: 1.1.1
    description: >-
      Controls usage of the host filesystem. Corresponds to the
      `allowedHostPaths` field in a PodSecurityPolicy. For more information,
      see
      https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
spec:
  crd:
    spec:
      names:
        kind: K8sPSPHostFilesystem
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          description: >-
            Controls usage of the host filesystem. Corresponds to the
            `allowedHostPaths` field in a PodSecurityPolicy. For more information,
            see
            https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems
          properties:
            allowedHostPaths:
              type: array
              description: "An array of hostpath objects, representing paths and read/write configuration."
              items:
                type: object
                properties:
                  pathPrefix:
                    type: string
                    description: "The path prefix that the host volume must match."
                  readOnly:
                    type: boolean
                    description: "when set to true, any container volumeMounts matching the pathPrefix must include `readOnly: true`."
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
          - name: allContainers
            expression: 'variables.containers + variables.initContainers + variables.ephemeralContainers'
          - name: allowedPaths
            expression: |
              !has(variables.params.allowedHostPaths) ? [] : variables.params.allowedHostPaths
          - name: volumes
            expression: |
              !has(variables.anyObject.spec.volumes) ? [] : variables.anyObject.spec.volumes.filter(volume, has(volume.hostPath))
          - name: badHostPaths
            expression: |
              variables.volumes.filter(volume, 
                (size(variables.allowedPaths) == 0) ||
                !(variables.allowedPaths.exists(allowedPath, 
                    volume.hostPath.path.startsWith(allowedPath.pathPrefix) && (
                    (!has(allowedPath.readOnly) || !(allowedPath.readOnly)) ||
                      (has(allowedPath.readOnly) && allowedPath.readOnly && !variables.allContainers.exists(c, 
                      c.volumeMounts.exists(m, m.name == volume.name && (!has(m.readOnly) || !m.readOnly)))))))
              ).map(volume, "{ hostPath: { path : " + volume.hostPath.path + " }, name: " + volume.name + "}").map(volume, "HostPath volume " + volume + " is not allowed, pod: " + object.metadata.name + ". Allowed path: " + variables.allowedPaths.map(path,  path.pathPrefix + ", readOnly: " + (path.readOnly ? "true" : "false") + "}").join(", "))
          validations:
          - expression: '(has(request.operation) && request.operation == "UPDATE") || size(variables.badHostPaths) == 0'
            messageExpression: 'variables.badHostPaths.join("\n")'
      - engine: Rego
        source:
          rego: |
            package k8spsphostfilesystem

            import data.lib.exclude_update.is_update

            violation[{"msg": msg, "details": {}}] {
                # spec.volumes field is immutable.
                not is_update(input.review)

                volume := input_hostpath_volumes[_]
                allowedPaths := get_allowed_paths(input)
                input_hostpath_violation(allowedPaths, volume)
                msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.review.object.metadata.name, allowedPaths])
            }

            input_hostpath_violation(allowedPaths, _) {
                # An empty list means all host paths are blocked
                allowedPaths == []
            }
            input_hostpath_violation(allowedPaths, volume) {
                not input_hostpath_allowed(allowedPaths, volume)
            }

            get_allowed_paths(arg) = out {
                not arg.parameters
                out = []
            }
            get_allowed_paths(arg) = out {
                not arg.parameters.allowedHostPaths
                out = []
            }
            get_allowed_paths(arg) = out {
                out = arg.parameters.allowedHostPaths
            }

            input_hostpath_allowed(allowedPaths, volume) {
                allowedHostPath := allowedPaths[_]
                path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
                not allowedHostPath.readOnly == true
            }

            input_hostpath_allowed(allowedPaths, volume) {
                allowedHostPath := allowedPaths[_]
                path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
                allowedHostPath.readOnly
                not writeable_input_volume_mounts(volume.name)
            }

            writeable_input_volume_mounts(volume_name) {
                container := input_containers[_]
                mount := container.volumeMounts[_]
                mount.name == volume_name
                not mount.readOnly
            }

            # This allows "/foo", "/foo/", "/foo/bar" etc., but
            # disallows "/fool", "/etc/foo" etc.
            path_matches(prefix, path) {
                a := path_array(prefix)
                b := path_array(path)
                prefix_matches(a, b)
            }
            path_array(p) = out {
                p != "/"
                out := split(trim(p, "/"), "/")
            }
            # This handles the special case for "/", since
            # split(trim("/", "/"), "/") == [""]
            path_array("/") = []

            prefix_matches(a, b) {
                count(a) <= count(b)
                not any_not_equal_upto(a, b, count(a))
            }

            any_not_equal_upto(a, b, n) {
                a[i] != b[i]
                i < n
            }

            input_hostpath_volumes[v] {
                v := input.review.object.spec.volumes[_]
                has_field(v, "hostPath")
            }

            # has_field returns whether an object has a field
            has_field(object, field) = true {
                object[field]
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

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/template.yaml
```
## Examples
<details>
<summary>host-filesystem</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostFilesystem
metadata:
  name: psp-host-filesystem
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedHostPaths:
    - readOnly: true
      pathPrefix: "/foo"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/constraint.yaml
```

</details>

<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-filesystem
spec:
  containers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /cache
      name: cache-volume
      readOnly: true
  volumes:
  - name: cache-volume
    hostPath:
      path: /tmp # directory location on host

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/example_disallowed.yaml
```

</details>
<details>
<summary>example-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-filesystem
spec:
  containers:
    - name: nginx
      image: nginx
      volumeMounts:
        - mountPath: /cache
          name: cache-volume
          readOnly: true
  volumes:
    - name: cache-volume
      hostPath:
        path: /foo/bar

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-ephemeral</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-filesystem
spec:
  ephemeralContainers:
  - name: nginx
    image: nginx
    volumeMounts:
    - mountPath: /cache
      name: cache-volume
      readOnly: true
  volumes:
  - name: cache-volume
    hostPath:
      path: /tmp # directory location on host

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/disallowed_ephemeral.yaml
```

</details>


</details><details>
<summary>no-host-paths</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPHostFilesystem
metadata:
  name: no-host-paths
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/no-host-paths/constraint.yaml
```

</details>

<details>
<summary>previously-allowed-path-disallowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-host-filesystem
spec:
  containers:
    - name: nginx
      image: nginx
      volumeMounts:
        - mountPath: /cache
          name: cache-volume
          readOnly: true
  volumes:
    - name: cache-volume
      hostPath:
        path: /foo/bar

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/psp-host-filesystem/example_allowed.yaml
```

</details>
<details>
<summary>no-volumes-is-allowed</summary>

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-volumes
spec:
  containers:
    - name: nginx
      image: nginx

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/pod-security-policy/host-filesystem/samples/no-host-paths/example_allowed_no_volumes.yaml
```

</details>


</details>