---
id: verifydeprecatedapi
title: Verify deprecated APIs
---

# Verify deprecated APIs

## Description
Verifies deprecated Kubernetes APIs to ensure all the API versions are up to date. This template does not apply to audit as audit looks at the resources which are already present in the cluster with non-deprecated API versions.

## Template
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: verifydeprecatedapi
  annotations:
    metadata.gatekeeper.sh/title: "Verify deprecated APIs"
    metadata.gatekeeper.sh/version: 1.0.0
    description: >-
      Verifies deprecated Kubernetes APIs to ensure all the API versions are up to date. This template does not apply to audit as audit looks at the resources which are already present in the cluster with non-deprecated API versions.
spec:
  crd:
    spec:
      names:
        kind: VerifyDeprecatedAPI
      validation:
        openAPIV3Schema:
          type: object
          properties:
            kvs:
              type: array
              description: Deprecated api versions and corresponding kinds
              items:
                type: object
                properties:
                  deprecatedAPI:
                    type: string
                    description: deprecated api
                    example: flowcontrol.apiserver.k8s.io/v1beta2
                  kinds:
                    type: array
                    items:
                      type: string
                    description: impacted list of kinds
                    example: '["FlowSchema", "PriorityLevelConfiguration"]'
                  targetAPI:
                    type: string
                    description: target api
                    example: flowcontrol.apiserver.k8s.io/v1beta3
            k8sVersion:
              type: number
              description: kubernetes version
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package verifydeprecatedapi

        violation[{"msg": msg}] {
          kvs := input.parameters.kvs[_]
          kvs.deprecatedAPI == input.review.object.apiVersion
          k := kvs.kinds[_]
          k == input.review.object.kind
          msg := get_message(input.review.object.kind, input.review.object.apiVersion, input.parameters.k8sVersion, kvs.targetAPI)
        }

        get_message(kind, apiVersion, k8sVersion, targetAPI) = msg {
          not match(targetAPI)
          msg := sprintf("API %v for %v is deprecated in Kubernetes version %v, please use %v instead", [kind, apiVersion, k8sVersion, targetAPI])
        }

        get_message(kind, apiVersion, k8sVersion, targetAPI) = msg {
          match(targetAPI)
          msg := sprintf("API %v for %v is deprecated in Kubernetes version %v, please see Kubernetes API deprecation guide", [kind, apiVersion, k8sVersion])
        }

        match(api) {
          api == "None"
        }

```

### Usage
```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/template.yaml
```
## Examples
<details>
<summary>verifydeprecatedapi-1.16</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.16
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "ReplicaSet", "StatefulSet", "DaemonSet"]
      - apiGroups: ["extensions"]
        kinds: ["PodSecurityPolicy", "ReplicaSet", "Deployment", "DaemonSet", "NetworkPolicy"]
  parameters:
    kvs: 
      - deprecatedAPI: "apps/v1beta1"
        kinds: ["Deployment", "ReplicaSet", "StatefulSet"]
        targetAPI: "apps/v1"
      - deprecatedAPI: "extensions/v1beta1"
        kinds: ["ReplicaSet", "Deployment", "DaemonSet"]
        targetAPI: "apps/v1"
      - deprecatedAPI: "extensions/v1beta1"
        kinds: ["PodSecurityPolicy"]
        targetAPI: "policy/v1beta1"
      - deprecatedAPI: "apps/v1beta2"
        kinds: ["ReplicaSet", "StatefulSet", "Deployment", "DaemonSet"]
        targetAPI: "apps/v1"
      - deprecatedAPI: "extensions/v1beta1"
        kinds: ["NetworkPolicy"]
        targetAPI: "networking.k8s.io/v1"
    k8sVersion: 1.16

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.16/constraint.yaml
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

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.16/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: apps/v1beta1
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

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.16/example_disallowed.yaml
```

</details>


</details><details>
<summary>verifydeprecatedapi-1.22</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.22
spec:
  match:
    kinds:
      - apiGroups: ["admissionregistration.k8s.io"]
        kinds: ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"]
      - apiGroups: ["apiextensions.k8s.io"]
        kinds: ["CustomResourceDefinition"]
      - apiGroups: ["apiregistration.k8s.io"]
        kinds: ["APIService"]
      - apiGroups: ["authentication.k8s.io"]
        kinds: ["TokenReview"]
      - apiGroups: ["authorization.k8s.io"]
        kinds: ["SubjectAccessReview"]
      - apiGroups: ["certificates.k8s.io"]
        kinds: ["CertificateSigningRequest"]
      - apiGroups: ["coordination.k8s.io"]
        kinds: ["Lease"]
      - apiGroups: ["extensions", "networking.k8s.io"]
        kinds: ["Ingress"]
      - apiGroups: ["networking.k8s.io"]
        kinds: ["IngressClass"]
      - apiGroups: ["rbac.authorization.k8s.io"]
        kinds: ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"]
      - apiGroups: ["scheduling.k8s.io"]
        kinds: ["PriorityClass"]
      - apiGroups: ["storage.k8s.io"]
        kinds: ["CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"]
  parameters:
    kvs:
      - deprecatedAPI: "admissionregistration.k8s.io/v1beta1"
        kinds: ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"]
        targetAPI: "admissionregistration.k8s.io/v1"
      - deprecatedAPI: "apiextensions.k8s.io/v1beta1"
        kinds: ["CustomResourceDefinition"]
        targetAPI: "apiextensions.k8s.io/v1"
      - deprecatedAPI: "apiregistration.k8s.io/v1beta1"
        kinds: ["APIService"]
        targetAPI: "apiregistration.k8s.io/v1"
      - deprecatedAPI: "authentication.k8s.io/v1beta1"
        kinds: ["TokenReview"]
        targetAPI: "authentication.k8s.io/v1"
      - deprecatedAPI: "authorization.k8s.io/v1beta1"
        kinds: ["SubjectAccessReview"]
        targetAPI: "authorization.k8s.io/v1"
      - deprecatedAPI: "certificates.k8s.io/v1beta1"
        kinds: ["CertificateSigningRequest"]
        targetAPI: "certificates.k8s.io/v1"
      - deprecatedAPI: "coordination.k8s.io/v1beta1"
        kinds: ["Lease"]
        targetAPI: "coordination.k8s.io/v1"
      - deprecatedAPI: "extensions/v1beta1"
        kinds: ["Ingress"]
        targetAPI: "networking.k8s.io/v1"
      - deprecatedAPI: "networking.k8s.io/v1beta1"
        kinds: ["Ingress", "IngressClass"]
        targetAPI: "networking.k8s.io/v1"
      - deprecatedAPI: "rbac.authorization.k8s.io/v1beta1"
        kinds: ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"]
        targetAPI: "rbac.authorization.k8s.io/v1"
      - deprecatedAPI: "scheduling.k8s.io/v1beta1"
        kinds: ["PriorityClass"]
        targetAPI: "scheduling.k8s.io/v1"
      - deprecatedAPI: "storage.k8s.io/v1beta1"
        kinds: ["CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"]
        targetAPI: "storage.k8s.io/v1"
    k8sVersion: 1.22

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.22/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: allowed-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx-example
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.22/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: disallowed-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  ingressClassName: nginx-example
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.22/example_disallowed.yaml
```

</details>


</details><details>
<summary>verifydeprecatedapi-1.25</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.25
spec:
  match:
    kinds:
      - apiGroups: ["batch"]
        kinds: ["CronJob"]
      - apiGroups: ["discovery.k8s.io"]
        kinds: ["EndpointSlice"]
      - apiGroups: ["events.k8s.io"]
        kinds: ["Event"]
      - apiGroups: ["autoscaling"]
        kinds: ["HorizontalPodAutoscaler"]
      - apiGroups: ["policy"]
        kinds: ["PodDisruptionBudget", "PodSecurityPolicy"]
      - apiGroups: ["node.k8s.io"]
        kinds: ["RuntimeClass"]
  parameters:
    kvs:
      - deprecatedAPI: "batch/v1beta1"
        kinds: ["CronJob"]
        targetAPI: "batch/v1"
      - deprecatedAPI: "discovery.k8s.io/v1beta1"
        kinds: ["EndpointSlice"]
        targetAPI: "discovery.k8s.io/v1"
      - deprecatedAPI: "events.k8s.io/v1beta1"
        kinds: ["Event"]
        targetAPI: "events.k8s.io/v1"
      - deprecatedAPI: "autoscaling/v2beta1"
        kinds: ["HorizontalPodAutoscaler"]
        targetAPI: "autoscaling/v2"
      - deprecatedAPI: "policy/v1beta1"
        kinds: ["PodDisruptionBudget"]
        targetAPI: "policy/v1"
      - deprecatedAPI: "policy/v1beta1"
        kinds: ["PodSecurityPolicy"]
        targetAPI: "None"
      - deprecatedAPI: "node.k8s.io/v1beta1"
        kinds: ["RuntimeClass"]
        targetAPI: "node.k8s.io/v1"
    k8sVersion: 1.25

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.25/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: allowed-cronjob
  namespace: default
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox:1.28
            imagePullPolicy: IfNotPresent
            command:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.25/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: disallowed-cronjob
  namespace: default
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox:1.28
            imagePullPolicy: IfNotPresent
            command:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.25/example_disallowed.yaml
```

</details>


</details><details>
<summary>verifydeprecatedapi-1.26</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.26
spec:
  match:
    kinds:
      - apiGroups: ["flowcontrol.apiserver.k8s.io"]
        kinds: ["FlowSchema", "PriorityLevelConfiguration"]
      - apiGroups: ["autoscaling"]
        kinds: ["HorizontalPodAutoscaler"]
  parameters:
    kvs: 
      - deprecatedAPI: "flowcontrol.apiserver.k8s.io/v1beta1"
        kinds: ["FlowSchema", "PriorityLevelConfiguration"]
        targetAPI: "flowcontrol.apiserver.k8s.io/v1beta3"
      - deprecatedAPI: "autoscaling/v2beta2"
        kinds: ["HorizontalPodAutoscaler"]
        targetAPI: "autoscaling/v2"
    k8sVersion: 1.26

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.26/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata:
  name: allowed-flowcontrol
  namespace: default
spec:
  matchingPrecedence: 1000
  priorityLevelConfiguration:
    name: exempt
  rules:
    - nonResourceRules:
      - nonResourceURLs:
          - "/healthz"
          - "/livez"
          - "/readyz"
        verbs:
          - "*"
      subjects:
        - kind: Group
          group:
            name: "system:unauthenticated"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.26/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta1
kind: FlowSchema
metadata:
  name: disallowed-flowcontrol
  namespace: default
spec:
  matchingPrecedence: 1000
  priorityLevelConfiguration:
    name: exempt
  rules:
    - nonResourceRules:
      - nonResourceURLs:
          - "/healthz"
          - "/livez"
          - "/readyz"
        verbs:
          - "*"
      subjects:
        - kind: Group
          group:
            name: "system:unauthenticated"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.26/example_disallowed.yaml
```

</details>


</details><details>
<summary>verifydeprecatedapi-1.27</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.27
spec:
  match:
    kinds:
      - apiGroups: ["storage.k8s.io"]
        kinds: ["CSIStorageCapacity"]
  parameters:
    kvs: 
      - deprecatedAPI: "storage.k8s.io/v1beta1"
        kinds: ["CSIStorageCapacity"]
        targetAPI: "storage.k8s.io/v1"
    k8sVersion: 1.27

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.27/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: storage.k8s.io/v1
kind: CSIStorageCapacity
metadata:
  name: allowed-csistoragecapacity
storageClassName: standard

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.27/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: storage.k8s.io/v1beta1
kind: CSIStorageCapacity
metadata:
  name: allowed-csistoragecapacity
  namespace: default
storageClassName: standard

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.27/example_disallowed.yaml
```

</details>


</details><details>
<summary>verifydeprecatedapi-1.29</summary>

<details>
<summary>constraint</summary>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VerifyDeprecatedAPI
metadata:
  name: verify-1.29
spec:
  match:
    kinds:
      - apiGroups: ["flowcontrol.apiserver.k8s.io"]
        kinds: ["FlowSchema", "PriorityLevelConfiguration"]
  parameters:
    kvs: 
      - deprecatedAPI: "flowcontrol.apiserver.k8s.io/v1beta2"
        kinds: ["FlowSchema", "PriorityLevelConfiguration"]
        targetAPI: "flowcontrol.apiserver.k8s.io/v1beta3"
    k8sVersion: 1.29

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.29/constraint.yaml
```

</details>

<details>
<summary>example-allowed</summary>

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata:
  name: allowed-flowcontrol
  namespace: default
spec:
  matchingPrecedence: 1000
  priorityLevelConfiguration:
    name: exempt
  rules:
    - nonResourceRules:
      - nonResourceURLs:
          - "/healthz"
          - "/livez"
          - "/readyz"
        verbs:
          - "*"
      subjects:
        - kind: Group
          group:
            name: "system:unauthenticated"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.29/example_allowed.yaml
```

</details>
<details>
<summary>example-disallowed</summary>

```yaml
apiVersion: flowcontrol.apiserver.k8s.io/v1beta2
kind: FlowSchema
metadata:
  name: disallowed-flowcontrol
  namespace: default
spec:
  matchingPrecedence: 1000
  priorityLevelConfiguration:
    name: exempt
  rules:
    - nonResourceRules:
      - nonResourceURLs:
          - "/healthz"
          - "/livez"
          - "/readyz"
        verbs:
          - "*"
      subjects:
        - kind: Group
          group:
            name: "system:unauthenticated"

```

Usage

```shell
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper-library/master/library/general/verifydeprecatedapi/samples/verify-1.29/example_disallowed.yaml
```

</details>


</details>