#!/bin/bash

# Look in the library and find every `template.yaml` file
TEMPLATE_PATHS=$(find . -name "*template.yaml")

FAILURE=false
for path in $TEMPLATE_PATHS; do

  # cut off the filename
  dir=$(dirname "$path")

  # the suite.yaml should be in the exact same directory as the template.yaml
  suite_path="${dir}/suite.yaml"  

  if ! [[ -s "$suite_path" ]]; then
    printf "  > ERROR: Directory '%s' must contain a non-empty suite.yaml file\n" "$dir"
    FAILURE=true
  fi
done

if "$FAILURE"; then
  exit 1
fi
