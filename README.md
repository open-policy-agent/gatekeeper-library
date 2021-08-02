# OPA Gatekeeper Library

A community-owned library of policies for the OPA Gatekeeper project.

## Usage

Apply the `template.yaml` and `constraint.yaml` provided in each directory under `library/`

For example

```bash
cd library/general/httpsonly/
kubectl apply -f template.yaml
kubectl apply -f samples/ingress-https-only/constraint.yaml
kubectl apply -f library/general/httpsonly/sync.yaml # optional: when GK is running with OPA cache
```

Note: Some policies should only be enforced for pods targeting a specific OS.
Refer to the [OS specific policies](./OS-specific-policies.md) page for more information.

## How to contribute to the library

### New policy

If you have a policy you would like to contribute, please submit a pull request.
Each new policy should contain:
* A constraint template with a `description` annotation and the parameter structure, if any, defined in `spec.crd.spec.validation.openAPIV3Schema`
* One or more sample constraints, each with an example of an allowed (`example_allowed.yaml`) and disallowed (`example_disallowed.yaml`) resource.
* The rego source, as `src.rego` and unit tests as `src_test.rego` in the corresponding subdirectory under `src/`

### Development

* policy code and tests are maintained in `src/` folder and then manually copied into `library/`
* run all tests with `./test.sh`
* run single test with `opa test src/<folder>/src.rego src/<folder>/src_test.rego --verbose`
* print results with `trace(sprintf("%v", [thing]))`
