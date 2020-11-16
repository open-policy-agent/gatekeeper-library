#!/bin/bash

set -eu

for folder in src/*/*
do
  src=$folder/src.rego
  test=$folder/src_test.rego
  # TODO: enforce coverage
  # needs https://github.com/open-policy-agent/opa/issues/2562 to see what was not covered
  # needs https://github.com/open-policy-agent/opa/issues/2139 to see verbose output when using coverage
  echo "opa test $src $test"
  opa test $src $test
done
