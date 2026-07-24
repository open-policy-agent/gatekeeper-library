---
id: storageclass
title: Storage Class
---

# Storage Class

## Description
Requires storage classes to be specified when used. Only Gatekeeper 3.9+ and non-ephemeral containers are supported.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sstorageclass
  annotations:
    metadata.gatekeeper.sh/title: "Storage Class"
    metadata.gatekeeper.sh/version: 1.1.2
    metadata.gatekeeper.sh/requires-sync-data: |
      "[
        [
          {
            "groups":["storage.k8s.io"],
            "versions": ["v1"],
            "kinds": ["StorageClass"]
          }
        ]
      ]"
    description: >-
      Requires storage classes to be specified when used. Only Gatekeeper 3.9+ and non-ephemeral containers are supported.
spec:
  crd:
    spec:
      names:
        kind: K8sStorageClass
      validation:
        openAPIV3Schema:
          type: object
          description: >-
            Requires storage classes to be specified when used.
          properties:
            includeStorageClassesInMessage:
              type: boolean
              default: true
            allowedStorageClasses:
              type: array
              description: "An optional allow-list of storage classes.  If specified, any storage class not in the `allowedStorageClasses` parameter is disallowed."
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sstorageclass

        is_pvc(obj) {
          obj.apiVersion == "v1"
          obj.kind == "PersistentVolumeClaim"
        }

        is_statefulset(obj) {
          obj.apiVersion == "apps/v1"
          obj.kind == "StatefulSet"
        }

        violation[{"msg": msg}] {
          not data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"]
          msg := sprintf("StorageClasses not synced. Gatekeeper may be misconfigured. Please have a cluster-admin consult the documentation.", [])
        }

        storageclass_allowed(name) {
          data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][name]
          # support both direct use of * and as the default value
          object.get(input.parameters, "allowedStorageClasses", ["*"])[_] == "*"
        }

        storageclass_allowed(name) {
          data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][name]
          input.parameters.allowedStorageClasses[_] == name
        }

        violation[{"msg": pvc_storageclass_badname_msg}] {
          is_pvc(input.review.object)
          not storageclass_allowed(input.review.object.spec.storageClassName)
        }
        pvc_storageclass_badname_msg := sprintf("pvc did not specify a valid storage class name <%v>. Must be one of [%v]", args) {
          input.parameters.includeStorageClassesInMessage
          object.get(input.parameters, "allowedStorageClasses", null) == null
          args := [
            input.review.object.spec.storageClassName,
            concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
          ]
        } else := sprintf("pvc did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", args) {
          input.parameters.includeStorageClassesInMessage
          object.get(input.parameters, "allowedStorageClasses", null) != null
          sc := {n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]} & {x | x = object.get(input.parameters, "allowedStorageClasses", [])[_]}
          args := [
            input.review.object.spec.storageClassName,
            concat(", ", sc)
          ]
        } else := sprintf(
          "pvc did not specify a valid storage class name <%v>.",
          [input.review.object.spec.storageClassName]
        )

        violation[{"msg": pvc_storageclass_noname_msg}] {
          is_pvc(input.review.object)
          not input.review.object.spec.storageClassName
        }
        pvc_storageclass_noname_msg := sprintf("pvc did not specify a storage class name. Must be one of [%v]", args) {
          input.parameters.includeStorageClassesInMessage
          args := [
            concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
          ]
        } else := sprintf(
          "pvc did not specify a storage class name.",
          []
        )

        violation[{"msg": statefulset_vct_badname_msg(vct)}] {
          is_statefulset(input.review.object)
          vct := input.review.object.spec.volumeClaimTemplates[_]
          not storageclass_allowed(vct.spec.storageClassName)
        }
        statefulset_vct_badname_msg(vct) := msg {
          input.parameters.includeStorageClassesInMessage
          object.get(input.parameters, "allowedStorageClasses", null) == null
          msg := sprintf(
              "statefulset did not specify a valid storage class name <%v>. Must be one of [%v]", [
              vct.spec.storageClassName,
              concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
          ])
        }
        statefulset_vct_badname_msg(vct) := msg {
          input.parameters.includeStorageClassesInMessage
          object.get(input.parameters, "allowedStorageClasses", null) != null
          sc := {n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]} & {x | x = object.get(input.parameters, "allowedStorageClasses", [])[_]}
          msg := sprintf(
              "statefulset did not specify an allowed and valid storage class name <%v>. Must be one of [%v]", [
              vct.spec.storageClassName,
              concat(", ", sc)
          ])
        }
        statefulset_vct_badname_msg(vct) := msg {
          not input.parameters.includeStorageClassesInMessage
          msg := sprintf(
            "statefulset did not specify a valid storage class name <%v>.", [
              vct.spec.storageClassName
          ])
        }

        violation[{"msg": statefulset_vct_noname_msg}] {
          is_statefulset(input.review.object)
          vct := input.review.object.spec.volumeClaimTemplates[_]
          not vct.spec.storageClassName
        }
        statefulset_vct_noname_msg := sprintf("statefulset did not specify a storage class name. Must be one of [%v]", args) {
          input.parameters.includeStorageClassesInMessage
          args := [
            concat(", ", [n | data.inventory.cluster["storage.k8s.io/v1"]["StorageClass"][n]])
          ]
        } else := sprintf(
          "statefulset did not specify a storage class name.",
          []
        )

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/template.yaml
```
## Examples
<details>
<summary>storageclass</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sStorageClass
metadata:
  name: storageclass
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["PersistentVolumeClaim"]
      - apiGroups: ["apps"]
        kinds: ["StatefulSet"]
  parameters:
    includeStorageClassesInMessage: true

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/constraint.yaml
```

</details>

<details>
<summary>example-allowed-pvc</summary>

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ok
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 8Gi
  storageClassName: somestorageclass

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_allowed_pvc.yaml
```

</details>
<details>
<summary>example-allowed-ss</summary>

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: volumeclaimstorageclass
spec:
  selector:
    matchLabels:
      app: volumeclaimstorageclass
  serviceName: volumeclaimstorageclass
  replicas: 1
  template:
    metadata:
      labels:
        app: volumeclaimstorageclass
    spec:
      containers:
      - name: main
        image: registry.k8s.io/nginx-slim:0.8
        volumeMounts:
        - name: data
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: "somestorageclass"
      resources:
        requests:
          storage: 1Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_allowed_ss.yaml
```

</details>
<details>
<summary>example-disallowed-pvc-badname</summary>

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: badstorageclass
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 8Gi
  storageClassName: badstorageclass

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_disallowed_pvc_badname.yaml
```

</details>
<details>
<summary>example-disallowed-ssvct-badnamename</summary>

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: badvolumeclaimstorageclass
spec:
  selector:
    matchLabels:
      app: badvolumeclaimstorageclass
  serviceName: badvolumeclaimstorageclass
  replicas: 1
  template:
    metadata:
      labels:
        app: badvolumeclaimstorageclass
    spec:
      containers:
      - name: main
        image: registry.k8s.io/nginx-slim:0.8
        volumeMounts:
        - name: data
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: "badstorageclass"
      resources:
        requests:
          storage: 1Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_disallowed_ssvct_badnamename.yaml
```

</details>
<details>
<summary>example-disallowed-pvc-nonamename</summary>

```yaml
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nostorageclass
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 8Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_disallowed_pvc_nonamename.yaml
```

</details>
<details>
<summary>example-disallowed-ssvct-nonamename</summary>

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: novolumeclaimstorageclass
spec:
  selector:
    matchLabels:
      app: novolumeclaimstorageclass
  serviceName: novolumeclaimstorageclass
  replicas: 1
  template:
    metadata:
      labels:
        app: novolumeclaimstorageclass
    spec:
      containers:
      - name: main
        image: registry.k8s.io/nginx-slim:0.8
        volumeMounts:
        - name: data
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 1Gi

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass/example_disallowed_ssvct_nonamename.yaml
```

</details>


</details><details>
<summary>storageclass-allowlist</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sStorageClass
metadata:
  name: allowed-storageclass
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["PersistentVolumeClaim"]
      - apiGroups: ["apps"]
        kinds: ["StatefulSet"]
  parameters:
    includeStorageClassesInMessage: true
    allowedStorageClasses:
      - allowed-storage-class

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass-allowlist/constraint.yaml
```

</details>

<details>
<summary>allowed-storage-class-pvc</summary>

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: allowed-storage-class-pvc
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 8Gi
  storageClassName: allowed-storage-class

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass-allowlist/example_allowed.yaml
```

</details>
<details>
<summary>disallowed-storage-class-pvc</summary>

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: disallowed-storage-class-pvc
spec:
  accessModes:
    - ReadWriteOnce
  volumeMode: Filesystem
  resources:
    requests:
      storage: 8Gi
  storageClassName: disallowed-storage-class

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/storageclass/samples/storageclass-allowlist/example_disallowed.yaml
```

</details>


</details>