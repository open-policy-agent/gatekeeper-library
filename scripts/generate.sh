#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

main() {
  for tmpl in $(find src -name 'constraint.tmpl'); do
    src_dir="$(dirname "${tmpl}")"
    lib_dir="library/${src_dir#src/}"
    if [[ ! -d ${lib_dir} ]]; then
      mkdir -p "${lib_dir}"
    fi

    echo "Generating ${lib_dir}/template.yaml"
    gomplate -f "${src_dir}/constraint.tmpl" > "${lib_dir}/template.yaml"

    for req in kustomization.yaml suite.yaml; do
      if [[ ! -f "${lib_dir}/${req}" ]]; then
        echo "${lib_dir}/${req} is missing"
        exit 1
      fi
    done

    if [[ ! -d "${lib_dir}/samples" ]]; then
      echo "${lib_dir}/samples is missing"
      exit 1
    fi
  done

  for tmpl in $(find library -name 'template.yaml'); do
    lib_dir="$(dirname "${tmpl}")"
    src_dir=src/${lib_dir#library/}
    if [[ ! -d "${src_dir}" ]]; then
      echo "${lib_dir} is missing the corresponding ${src_dir} folder"
      exit 1
    fi

    for req in src.rego src_test.rego constraint.tmpl; do
      if [[ ! -f "${src_dir}/${req}" ]]; then
        echo "${src_dir}/${req} is missing"
        exit 1
      fi
    done
  done
}

main
