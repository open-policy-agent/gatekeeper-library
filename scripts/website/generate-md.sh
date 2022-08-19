#!/bin/bash

set -o errexit

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

getName(){
    name=$(yq e '.spec.crd.spec.names.kind' $1)
    echo "$name"
}

getDescription() {
    description=$(yq e '.metadata.annotations.description' $1)
    echo "$description"
}

getTitle() {
    title=$(yq e '.metadata.annotations."metadata.gatekeeper.sh/title"' $1)
    echo "$title"
}

getExamples() {
    allDetailsExample=""
    for i in $(ls -d ${1}samples/*/)
    do
        constraint=$(cat ${i}/constraint.yaml)
        constraintExample="<details>\n<summary>constraint</summary>\n\n\`\`\`yaml\n$constraint\n\`\`\`\n\n</details>"

        # find all files that contain the word "allowed" in the filename                
        for j in $(find ${i} -maxdepth 1 -name "*allowed*")
        do
            # if file does not have the word "disallowed" in the filename, then it is allowed example.
            if [[ "${j}" != *"disallowed"* ]]; then
                allowedExampleFilePath="${j}"
                if [ -f "$allowedExampleFilePath" ]; then
                    allowed=$(cat ${j})
                    allowedExample="<details>\n<summary>$(basename ${j} .yaml)</summary>\n\n\`\`\`yaml\n$allowed\n\`\`\`\n\n</details>"
                fi
            fi
        done

        # get the disallowed example if it exists
        allDisallowedExample=""
        for j in $(find ${i} -maxdepth 1 -name "*disallowed*")
        do
            disallowed=$(cat ${j})
            disAllowedExample="<details>\n<summary>$(basename ${j} .yaml)</summary>\n\n\`\`\`yaml\n$disallowed\n\`\`\`\n\n</details>"
            allDisallowedExample="$allDisallowedExample$disAllowedExample\n"
        done

        # format constraint, allowed, and disallowed examples as collapsable sections for markdown.
        outerDetail="<details>\n<summary>$(basename ${i})</summary><blockquote>\n\n$constraintExample\n$allowedExample\n$allDisallowedExample\n\n</blockquote></details>"

        allDetailsExample="$allDetailsExample$outerDetail\n"
    done
    echo "$allDetailsExample"
}

updateReadme() {
    introContent=$(cat README.md)
    introContent=${introContent//$'\n'/\\n}
    sed -e "s~%CONTENT%~$introContent~g" $SCRIPT_DIR/readme-template.md > website/docs/intro.md
}

updatePSPReadme() {
    pspIntroContent=$(cat library/pod-security-policy/README.md)
    pspIntroContent=${pspIntroContent//$'\n'/\\n}
    sed -e "s~%CONTENT%~$pspIntroContent~g" $SCRIPT_DIR/pspreadme-template.md > website/docs/pspintro.md
}

# main
# list all the directories in the library directory
for i in $(ls -d library/*/)
do
    # list all the policy directories
    for j in $(ls -d ${i}*/)
    do
        echo "Generating markdown for ${j}"

        # get filename from path
        fileName=$(basename ${j})

        # get name and title from constraint template
        name=$(getName ${j}template.yaml)
        title=$(getTitle ${j}template.yaml)

        # get description from constraint template and escape newlines
        description=$(getDescription ${j}template.yaml)
        description=${description//$'\n'/\\n}

        # get content of the constraint template and escape newlines
        templateContent=$(cat ${j}template.yaml)
        templateContent=${templateContent//$'\n'/\\n}

        # get examples (constraint, allowed and disallowed examples) from samples directory and escape newlines
        examples=$(getExamples ${j})
        examples=${examples//$'\n'/\\n}

        # generate markdown from template
        sed -e "s/%FILENAME%/$fileName/g" -e "s/%NAME%/$name/g" -e "s/%TITLE%/$title/g" -e "s~%DESCRIPTION%~$description~g" -e "s~%TEMPLATE%~$templateContent~g" -e "s~%EXAMPLES%~$examples~g" $SCRIPT_DIR/template.md > website/docs/$fileName.md
    done
done

# update main intoduction page
updateReadme

# update PSP introduction page
updatePSPReadme
