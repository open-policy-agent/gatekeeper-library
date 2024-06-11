---
id: volumeresources
title: Container emptyDir Volume Resources
---

# Container emptyDir Volume Resources

## Description
Container emptyDir volume resources to be within the specified maximum values.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8svolumerequests
  annotations:
    metadata.gatekeeper.sh/title: "Container emptyDir Volume Resources"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Container emptyDir volume resources to be within the specified maximum values.
spec:
  crd:
    spec:
      names:
        kind: K8sVolumeRequests
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          type: object
          properties:
            volumesizelimit:
              description: "The maximum allowed emptyDir size limit on a volume."
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8svolumerequests

        violation[{"msg": msg}] {
            vols := input.review.object.spec.volumes[_]
            emptydir := vols.emptyDir
            not has_key(emptydir, "sizeLimit")
            msg := sprintf("Volume '%v' is not allowed, do not have set sizelimit", [vols.name])
        }

        violation[{"msg": msg}] {
            vols := input.review.object.spec.volumes[_]
            emptydir_orig := vols.emptyDir.sizeLimit
            size := canonify_size(emptydir_orig)
            max_size_orig := input.parameters.volumesizelimit
            max_size := canonify_size(max_size_orig)
            size > max_size
            msg := sprintf("volume <%v> size limit <%v> is higher than the maximum allowed of <%v>", [vols.name, emptydir_orig, max_size_orig])
        }

        has_key(object, key) {
            type_name(object[key])
        }

        size_multiple("E") = 1000000000000000000000

        # 10 ** 18
        size_multiple("P") = 1000000000000000000

        # 10 ** 15
        size_multiple("T") = 1000000000000000

        # 10 ** 12
        size_multiple("G") = 1000000000000

        # 10 ** 9
        size_multiple("M") = 1000000000

        # 10 ** 6
        size_multiple("k") = 1000000

        # 10 ** 3
        size_multiple("") = 1000

        # Kubernetes accepts millibyte precision when it probably shouldn't.
        # https://github.com/kubernetes/kubernetes/issues/28741
        # 10 ** 0
        size_multiple("m") = 1

        # 1000 * 2 ** 10
        size_multiple("Ki") = 1024000

        # 1000 * 2 ** 20
        size_multiple("Mi") = 1048576000

        # 1000 * 2 ** 30
        size_multiple("Gi") = 1073741824000

        # 1000 * 2 ** 40
        size_multiple("Ti") = 1099511627776000

        # 1000 * 2 ** 50
        size_multiple("Pi") = 1125899906842624000

        # 1000 * 2 ** 60
        size_multiple("Ei") = 1152921504606846976000

        canonify_size(orig) = new {
        	is_number(orig)
        	new := orig * 1000
        }

        get_suffix(size) = suffix {
        	is_string(size)
        	count(size) > 0
        	suffix := substring(size, count(size) - 1, -1)
        	size_multiple(suffix)
        }

        get_suffix(size) = suffix {
        	is_string(size)
        	count(size) > 1
        	suffix := substring(size, count(size) - 2, -1)
        	size_multiple(suffix)
        }

        get_suffix(size) = suffix {
        	is_string(size)
        	count(size) > 1
        	not size_multiple(substring(size, count(size) - 1, -1))
        	not size_multiple(substring(size, count(size) - 2, -1))
        	suffix := ""
        }

        get_suffix(size) = suffix {
        	is_string(size)
        	count(size) == 1
        	not size_multiple(substring(size, count(size) - 1, -1))
        	suffix := ""
        }

        get_suffix(size) = suffix {
        	is_string(size)
        	count(size) == 0
        	suffix := ""
        }

        canonify_size(orig) = new {
        	is_number(orig)
        	new := orig * 1000
        }

        canonify_size(orig) = new {
        	not is_number(orig)
        	suffix := get_suffix(orig)
        	raw := replace(orig, suffix, "")
        	regex.match("^[0-9]+(\\.[0-9]+)?$", raw)
        	new := to_number(raw) * size_multiple(suffix)
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
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/volumeresources/template.yaml
```
## Examples
<details>
<summary>volumeresources</summary>

<details>
<summary>constraint</summary>

```yaml
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sVolumeRequests
metadata:
  name: container-emptydir-limit
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
      - apiGroups: ["apps"]
        kinds: ["Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"]
  parameters:
    volumesizelimit: 1Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/volumeresources/samples/container-emptydir-limit/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: allowed-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
        volumeMounts:
        - mountPath: /demo
          name: demo-volume
      volumes:
      - name: demo-volume
        emptyDir: 
          sizeLimit: 16Mi
          medium: Memory

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/volumeresources/samples/container-emptydir-limit/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: disallowed-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
        volumeMounts:
        - mountPath: /demo
          name: demo-volume
      volumes:
      - name: demo-volume
        emptyDir: {}

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/volumeresources/samples/container-emptydir-limit/example_disallowed.yaml
```

</details>
<details>
<summary>example-disallowed-muti</summary>

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: disallowed-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
        volumeMounts:
        - mountPath: /demo
          name: demo-volume
        - mountPath: /demo-1
          name: demo-volume-1
      volumes:
      - name: demo-volume
        emptyDir: 
          sizeLimit: 16Mi
          medium: Memory
      - name: demo-volume-1
        emptyDir: 
          sizeLimit: 2Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/volumeresources/samples/container-emptydir-limit/example_disallowed_muti.yaml
```

</details>


</details>