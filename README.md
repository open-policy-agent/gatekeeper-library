# OPA Gatekeeper Library

This repository is a community-owned library of policies for the OPA Gatekeeper project.

## How to use the library

The easiest way to apply a policy from this library is to download and apply the `template.yaml` and a sample `constraint.yaml` provided in each policy directory

For example

    cd library/general/httpsonly/
    kubectl apply -f template.yaml
    kubectl apply -f samples/ingress-https-only/constraint.yaml

## How to contribute to the library

TODO.
