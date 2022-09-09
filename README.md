# OPA Gatekeeper Library

A community-owned library of policies for the [OPA Gatekeeper project](https://open-policy-agent.github.io/gatekeeper/website/docs/).

## Usage

### kustomize

You can use [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) to install some or all of the templates alongside your own contraints.

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

```
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

### Development

* policy code and tests are maintained in `src/<policy-name>/src.rego` and `src/<policy-name>/src_test.rego`
* `make generate` will generate `library/<policy-name>/template.yaml` from `src/<policy-name>/src.rego` using [gomplate](https://docs.gomplate.ca/).
* `make generate-website-docs` will generate the markdown files required for the website.
* run all tests with `./test.sh`
* run single test with `opa test src/<folder>/src.rego src/<folder>/src_test.rego --verbose`
* print results with `trace(sprintf("%v", [thing]))`
