#!/bin/bash

set -eu

for folder in src/*/*
do
  if [[ "${folder}" == src/v1* ]] ; then
    continue
  fi

  # Ensure OPA strict mode compliance
  # https://www.openpolicyagent.org/docs/latest/policy-language/#strict-mode
  opa check --v0-compatible --strict ${folder}

  # TODO: enforce coverage
  # needs https://github.com/open-policy-agent/opa/issues/2562 to see what was not covered
  # needs https://github.com/open-policy-agent/opa/issues/2139 to see verbose output when using coverage
  echo "opa test --v0-compatible ${folder}/*.rego"
  opa test --v0-compatible ${folder}/*.rego
done

for folder in src/v1/*/*
do
  opa check --strict ${folder}

  echo "opa test ${folder}/*.rego"
  opa test ${folder}/*.rego
done
