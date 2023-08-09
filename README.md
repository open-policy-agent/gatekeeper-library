# OPA Gatekeeper Library
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/gatekeeper-policies)](https://artifacthub.io/packages/search?repo=gatekeeper-policies)

A community-owned library of policies for the [OPA Gatekeeper project](https://open-policy-agent.github.io/gatekeeper/website/docs/).

## Validation and Mutation
The library consists of two main components: `Validation` and `Mutation`.
- Validation: Gatekeeper can validate resources in the cluster against Gatekeeper validation policies, such as these defined in the library. The policies are defined as `ConstraintTemplates` and `Constraints`. `ConstraintTemplates` can be applied directly to a cluster and then `Constraints` can be applied to customize policy to fit your specific needs.
- Mutation: Gatekeeper can mutate resources in the cluster against the Gatekeeper mutation policies, such as these defined in the library. Mutation policies are only examples, they should be customized to meet your needs before being applied.

## Usage

### kustomize

You can use [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) to install some or all of the templates alongside your own constraints.

First, create a `kustomization.yaml` file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- github.com/open-policy-agent/gatekeeper-library/library
# You can optionally install a subset by specifying a subfolder, or specify a commit SHA
# - github.com/open-policy-agent/gatekeeper-library/library/pod-security-policy?ref=0c82f402fb3594097a90d15215ae223267f5b955
- constraints.yaml
```

Then define your constraints in a file called `constraints.yaml` in the same directory. Example constraints can be found in the "samples" folders.

You can install everything with `kustomize build . | kubectl apply -f -`.

More information can be found in the [kustomization documentation](https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/).

### kubectl

Instead of using kustomize, you can directly apply the `template.yaml` and `constraint.yaml` provided in each directory under `library/`

For example

```bash
cd library/general/httpsonly/
kubectl apply -f template.yaml
kubectl apply -f samples/ingress-https-only/constraint.yaml
kubectl apply -f library/general/httpsonly/sync.yaml # optional: when GK is running with OPA cache
```

## Testing

The `suite.yaml` files define test cases for each ConstraintTemplate in the library.
Changes to gatekeeper-library ConstraintTemplates may be tested with the gator CLI:

```bash
gatekeeper-library$ gator verify ./...
```

The gator CLI may be downloaded from the Gatekeeper
[releases page](https://github.com/open-policy-agent/gatekeeper/releases).

## How to contribute to the library

### New policy

If you have a policy you would like to contribute, please submit a pull request.
Each new policy should contain:

* A constraint template named `src/<policy-name>/constraint.tmpl` with a `description` annotation and the parameter structure, if any, defined in `spec.crd.spec.validation.openAPIV3Schema`. The template is rendered using [gomplate](https://docs.gomplate.ca/).
* One or more sample constraints, each with an example of an allowed (`example_allowed.yaml`) and disallowed (`example_disallowed.yaml`) resource under `library/<policy-name>/samples/<policy-name>`
* `kustomization.yaml` and `suite.yaml` under `library/<policy-name>`
* The rego source, as `src.rego` and unit tests as `src_test.rego` in the corresponding subdirectory under `src/<policy-name>`
* [Versioning](https://docs.google.com/document/d/1IYiypA-mRcdfSVfmoeyuaeG8XtA1u4GkcqH3kEkv2uw/edit) has been introduced for Gatekeeper Library policies. Please make sure to add or bump the version of the policy as per the guidelines in the `src/<policy-name>/constraint.tmpl` annotation.
  * Major version bump required: Whenever there is a breaking change in the policy e.g.  updating template Kind, updating existing parameter schema, adding the `requires-sync-data` annotation to sync new data, or any other breaking changes
  * Minor version bump required: Whenever there is a backward compatible change in the policy e.g. adding a parameter, updating Rego logic
  * Patch version bump required: Whenever there is a simple backward compatible change in the policy, e.g. Simple Rego fix, updating policy metadata
  * Note: Sample constraints, mutations, and expansion templates are provided as examples, and severable changes do not require a version bump.

### Development

* policy code and tests are maintained in `src/<policy-name>/src.rego` and `src/<policy-name>/src_test.rego`
* `make generate` will generate `library/<policy-name>/template.yaml` from `src/<policy-name>/src.rego` using [gomplate](https://docs.gomplate.ca/).
* `make generate-website-docs` will generate the markdown files required for the website.
* `make generate-artifacthub-artifacts` will generate or update the artifact hub packages and associated `artifacthub-pkg.yml` file under `/artifacthub` directory.
* `make generate-all` will generate all artifacts above.
* `make validate` will run validation checks on the library repo. Currently it validates directory structure of `website/docs` directory.
* `make unit-test` will run all unit tests in the scripts directory.
* run all tests with `./test.sh`
* run single test with `opa test src/<folder>/src.rego src/<folder>/src_test.rego --verbose`
* print results with `trace(sprintf("%v", [thing]))`
