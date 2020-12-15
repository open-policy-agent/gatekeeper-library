# OPA Gatekeeper Library

This repository is a community-owned library of policies for the OPA Gatekeeper project.

## How to use the library

The easiest way to apply a policy from this library is to download and apply the `constraint.yaml` and `template.yaml` provided in each directory

For example

    cd library/general/httpsonly/
    kubectl apply -f constraint.yaml
    kubectl apply -f template.yaml

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
