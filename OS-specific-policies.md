# OS Specific Policies

Kubernetes allows for pods/containers targeting different operating systems to be scheduled into the same cluster and different operating systems and can behave differently depending on what OS the pods/containers are targeting.

This guide will help you configure policies that are meant only to specific operating systems.

## Usage

### Determine how your cluster will identify target OS

Unfortunately there is no definitive way identify which OS a pod is targeted for.
If you would like to enforce OS-specific policies in your cluster you should first determine how your cluster will identify the target OS for pods.

Policies in this repository will use [nodeSelectors](https://v1-18.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector) against the well-known [kubernetes.io\os](https://kubernetes.io/docs/reference/labels-annotations-taints/#kubernetes-io-os) label for pods. This is the simplest way to identifying the target OS for a pod but other mechanisms like [Runtime Classes](https://kubernetes.io/docs/concepts/containers/runtime-class/) exist as well and will follow the same procedure for enabling policy enforcement.

### Add a policy requiring all pods to identify an OS

After you have selected how you would like your cluster to identify the target OS for pods create a policy to ensure **every** pod admitted into your cluster specifies an OS.

Example:

```bash
cd library/general/requirednodeselectors
kubectl apply -f template.yaml
kubectl apply -f samples/require-os-node-selector/constraint.yaml
```

### Add OS specific policies

1. Include a check for your targeted OS in the rego for your policy. This check should skip policy enforcement if the OS does not match and enforce policy enforcement if the OS does match.

    Example: The function `isWindowsPod` in the [windows-runasusername](./library/pod-security-policy/windows-runasusername/template.yaml) template.

1. Add OS specific policies to your cluster.

    Example:

    ```bash
    cd library/general/windows-container-resources
    kubectl apply -f template.yaml
    kubectl apply -f samples/constraint.yaml
    ```

Some examples of OS specific policies include:

- [windows-container-resources](./library/general/windows-container-resources)
- [windows-runasusername](./library/pod-security-policy/windows-runasusername)
