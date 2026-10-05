#!/bin/bash

set -eu

# Directories whose Rego is v1 syntax. Gatekeeper rejects `import rego.v1`,
# so these modules are compiled with source.version "v1" and tested with
# --v1-compatible. Everything else stays Rego v0 until it is migrated.
v1_policies="
src/pod-security-policy/privileged-containers
"

is_v1_policy() {
  printf '%s\n' ${v1_policies} | grep -Fxq "$1"
}

opa_major() {
  opa version | awk '/^Version:/ { split($2, v, "."); print v[1]; exit }'
}

has_v1_flag() {
  opa test --help 2>&1 | grep -q -- '--v1-compatible'
}

for folder in src/*/*; do
  [ -d "${folder}" ] || continue

  flags=""
  if is_v1_policy "${folder}"; then
    if has_v1_flag; then
      flags="--v1-compatible"
    else
      echo "skipping ${folder}: OPA $(opa version | awk '/^Version:/ { print $2 }') cannot parse Rego v1"
      continue
    fi
  elif [ "$(opa_major)" = "1" ]; then
    flags="--v0-compatible"
  fi

  echo "opa check --strict ${flags} ${folder}"
  # shellcheck disable=SC2086
  opa check --strict ${flags} "${folder}"

  echo "opa test ${flags} ${folder}/*.rego"
  # shellcheck disable=SC2086
  opa test ${flags} ${folder}/*.rego
done
