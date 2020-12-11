# OPA Gatekeeper Library

This repository is a community-owned library of policies for the OPA Gatekeeper project.

## How to use the library

The easiest way to apply a policy from this library is to download and apply the `constraint.yaml` and `template.yaml` provided in each directory

For example

    cd library/general/httpsonly/
    kubectl apply -f constraint.yaml
    kubectl apply -f template.yaml

## How to contribute to the library

If you have a policy you would like to contribute to the library, please feel free to submit a pull request. Each new policy contribution should contain the following:
* A constraint template with a `description` annotation and the parameter structure, if any, defined in `spec.crd.spec.validation.openAPIV3Schema`
* One or more sample constraints, each with an example of an allowed (`example_allowed.yaml`) and disallowed (`example_disallowed.yaml`) resource.
* The rego source, as `src.rego` and unit tests as `src_test.rego` in the corresponding subdirectory under `src/`
