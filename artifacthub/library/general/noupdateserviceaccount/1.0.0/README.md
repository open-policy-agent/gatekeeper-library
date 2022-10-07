# NoUpdateServiceAccount

**NOTE:** This policy is ignored in `audit` mode, because it only blocks
updates to existing resources, not specific configurations.

The `NoUpdateServiceAccount` constraint blocks updating the service account on
resources that abstract over Pods.

This policy helps prevent workloads with "update-self" permissions from
escalating further in the cluster by selecting a new service account to
run as. It is especially useful for workloads running in sensitive
namespaces like `kube-system`, where nearby service accounts are likely to
have cluster admin rights.
