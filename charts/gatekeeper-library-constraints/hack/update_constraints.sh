#!/bin/bash

# Only works for validation components.

for file in ../crds/*; do

    FILENAME=$(echo "${file##*/}" | xargs)
    
    echo -e "Updating Gatekeeper Library Constraints from Constraint Templates:\nvalidation-${FILENAME}\n"

    touch "../templates/validation-${FILENAME}"
done

exit
