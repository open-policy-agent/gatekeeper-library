# Gatekeeper Library Constraint Templates

[Gatekeeper Library](https://open-policy-agent.github.io/gatekeeper-library/website/) is a community-owned library of policies for the [OPA Gatekeeper project](https://open-policy-agent.github.io/gatekeeper/website/docs/). It consists of two main components: `Validation` and `Mutation`.

This chart bootstraps [Gatekeeper Library](https://open-policy-agent.github.io/gatekeeper-library/website/) constraint templates on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.7+
- Gatekeeper 3.9+

## Get Repository Info

```console
helm repo add gatekeeper-library starlightromero/gatekeeper-library-crds
helm repo update
```

_See [helm repository](https://helm.sh/docs/helm/helm_repo/) for command documentation._

## Install Chart

```console
helm install [RELEASE_NAME] starlightromero/gatekeeper-library-crds
```

_See [helm install](https://helm.sh/docs/helm/helm_install/) for command documentation._

## Uninstall Chart

```console
helm uninstall [RELEASE_NAME]
```

This removes all the Kubernetes components associated with the chart and deletes the release.

_See [helm uninstall](https://helm.sh/docs/helm/helm_uninstall/) for command documentation._
