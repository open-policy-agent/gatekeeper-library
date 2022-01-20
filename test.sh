#!/bin/bash

set -eu

for folder in src/*/*
do
  # TODO: enforce coverage
  # needs https://github.com/open-policy-agent/opa/issues/2562 to see what was not covered
  # needs https://github.com/open-policy-agent/opa/issues/2139 to see verbose output when using coverage
  echo "opa test ${folder}/*.rego"
  opa test ${folder}/*.rego
done
