package k8spspseccomp

# Annotation based seccomp with containers
test_input_annotation_seccomp_empty_parameters {
    inp := {"review": get_object(pod_annotation, {}, single_container, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_allowed_all {
    inp := {"review": get_object(pod_annotation, {}, single_container, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_allowed_in_list {
    inp := {"review": get_object(pod_annotation, {}, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_not_allowed_not_in_list {
    inp := {"review": get_object(pod_annotation, {}, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_pod_multiple_empty_parameters {
    inp := {"review": get_object(pod_annotation, {}, multiple_containers, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 2
}

test_input_annotation_seccomp_pod_multiple_allowed_all {
    inp := {"review": get_object(pod_annotation, {}, multiple_containers, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_multiple_allowed_in_list {
    inp := {"review": get_object(pod_annotation, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_multiple_not_allowed_not_in_list {
    inp := {"review": get_object(pod_annotation, {}, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_annotation_seccomp_container_allowed_all {
    inp := {"review": get_object(container_annotation, {}, single_container, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_container_allowed_in_list {
    inp := {"review": get_object(container_annotation, {}, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_container_not_allowed_not_in_list {
    inp := {"review": get_object(container_annotation, {}, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_containers_allowed_in_list {
    inp := {"review": get_object(container_annotations, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_containers_not_allowed_not_in_list {
    inp := {"review": get_object(container_annotations, {}, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_annotation_seccomp_containers_mixed {
    inp := {"review": get_object(container_annotations_mixed, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_containers_mixed_missing {
    inp := {"review": get_object(container_annotation, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_containers_allowed_in_list_multiple {
    inp := {"review": get_object(container_annotations_mixed, {}, multiple_containers, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_container {
    inp := {"review": get_object(pod_container_annotations, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_container_not_allowed {
    inp := {"review": get_object(pod_container_annotations, {}, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_annotation_seccomp_pod_container_both_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, multiple_containers, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_container_mixed_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_pod_container_mixed_not_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_annotation_seccomp_pod_container_both_allowed_reversed {
    inp := {"review": get_object(pod_container_annotations_mixed_rev, {}, multiple_containers, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_container_mixed_allowed_reversed {
    inp := {"review": get_object(pod_container_annotations_mixed_rev, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_pod_container_mixed_not_allowed_reversed {
    inp := {"review": get_object(pod_container_annotations_mixed_rev, {}, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

# Annotation based seccomp with init containers
test_input_annotation_seccomp_pod_initcontainer_both_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, {}, multiple_containers), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_annotation_seccomp_pod_initcontainer_mixed_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, {}, multiple_containers), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_annotation_seccomp_pod_initcontainer_mixed_not_allowed {
    inp := {"review": get_object(pod_container_annotations_mixed, {}, {}, multiple_containers), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

# securityContext based seccomp with containers
test_input_seccomp_empty_parameters {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_allowed_all {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_allowed_in_list {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_not_allowed_not_in_list {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_pod_multiple_empty_parameters {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_pod_multiple_allowed_all {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_multiple_allowed_in_list {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_multiple_not_allowed_not_in_list {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_pod_localhost_allowed_wrong_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_sc}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_pod_localhost_allowed_no_specified_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_sc_localhost_no_file}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_pod_localhost_allowed_wildcard_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_sc_localhost_wildcard_file}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_localhost_allowed_annotation_wildcard_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_localhost_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_localhost_allowed_both_wildcard_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_localhost_wildcard_both}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_not_allowed_not_configured {
    inp := {"review": get_object({}, {}, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_not_allowed_multiple_not_configured {
    inp := {"review": get_object({}, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_container_allowed_all {
    inp := {"review": get_object({}, {}, single_container_sc, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_container_allowed_in_list {
    inp := {"review": get_object({}, {}, single_container_sc, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_container_not_allowed_not_in_list {
    inp := {"review": get_object({}, {}, single_container_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_containers_allowed_in_list {
    inp := {"review": get_object({}, {}, multiple_containers_sc, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_containers_not_allowed_not_in_list {
    inp := {"review": get_object({}, {}, multiple_containers_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_containers_mixed {
    inp := {"review": get_object({}, {}, multiple_containers_sc_mixed, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_containers_mixed_missing {
    inp := {"review": get_object({}, {}, multiple_containers_sc_missing, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_containers_allowed_in_list_multiple {
    inp := {"review": get_object({}, {}, multiple_containers_sc_mixed, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers_sc_missing, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container_mixed_not_allowed_but_exempt {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_exempt}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container_not_allowed {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers_sc_missing, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_pod_container_both_allowed {
    inp := {"review": get_object({}, context_localhost, multiple_containers_sc_missing, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container_mixed_allowed {
    inp := {"review": get_object({}, context_localhost, multiple_containers_sc_missing, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_pod_container_mixed_not_allowed {
    inp := {"review": get_object({}, context_localhost, multiple_containers_sc_missing, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

# securityContext based seccomp with init containers
test_input_seccomp_pod_initcontainer_both_allowed {
    inp := {"review": get_object({}, context_localhost, {}, multiple_containers_sc_missing), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_initcontainer_mixed_allowed {
    inp := {"review": get_object({}, context_localhost, {}, multiple_containers_sc_missing), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_pod_initcontainer_mixed_not_allowed {
    inp := {"review": get_object({}, context_localhost, {}, multiple_containers_sc_missing), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

# Both annotation and securityContext based seccomp mixed
test_input_both_seccomp_pod_context_container_annotation {
    inp := {"review": get_object(container_annotation_unconfined, context_runtimedefault, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_both_seccomp_pod_annotation_container_context {
    inp := {"review": get_object(pod_annotation_unconfined, {}, single_container_sc, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_both_seccomp_pod_context_and_annotation {
    inp := {"review": get_object(pod_annotation, context_runtimedefault, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_both_seccomp_container_context_and_annotation {
    inp := {"review": get_object(container_annotation, {}, single_container_sc, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_both_seccomp_pod_context_container_annotation_not_allowed {
    inp := {"review": get_object(container_annotation_unconfined, context_runtimedefault, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_both_seccomp_pod_annotation_container_context_not_allowed {
    inp := {"review": get_object(pod_annotation_unconfined, {}, single_container_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_both_seccomp_pod_context_and_annotation_not_allowed {
    inp := {"review": get_object(pod_annotation, context_runtimedefault, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_both_seccomp_container_context_and_annotation_not_allowed {
    inp := {"review": get_object(container_annotation, {}, single_container_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_both_seccomp_pod_context_container_annotation_multiple_mixed {
    inp := {"review": get_object(container_annotation, context_unconfined, multiple_containers_sc_missing, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 1
}

# Testing translation between annotation and securityContext
test_translation_seccomp_allowed_annotation_all {
    inp := {"parameters": input_parameters_annotation}
    output := get_allowed_profiles with input as inp
    output == allowed_full_translated_annotation_style
}

test_translation_seccomp_allowed_context_all {
    inp := {"parameters": input_parameters_sc}
    output := get_allowed_profiles with input as inp
    output == allowed_full_translated
}

test_translation_seccomp_allowed_context_localhost_wildcard_file {
    inp := {"parameters": input_parameters_sc_localhost_wildcard_file}
    output := get_allowed_profiles with input as inp
    output == {"Localhost", "localhost/*"}
}

test_translation_seccomp_allowed_context_localhost_no_file {
    inp := {"parameters": input_parameters_sc_localhost_no_file}
    output := get_allowed_profiles with input as inp
    output == {"Localhost"}
}

test_input_translation_seccomp_annotation_match_allowed_context {
    inp := {"review": get_object(container_annotation, {}, single_container, {}), "parameters": input_parameters_sc}
    results := violation with input as inp
    count(results) == 0
}

test_input_translation_seccomp_context_match_allowed_annotation {
    inp := {"review": get_object({}, {}, single_container_sc, {}), "parameters": input_parameters_annotation}
    results := violation with input as inp
    count(results) == 0
}

test_input_translation_seccomp_context_localhost_allowed_annotation {
    inp := {"review": get_object({}, context_localhost1, single_container, {}), "parameters": input_parameters_annotation}
    results := violation with input as inp
    count(results) == 0
}

test_input_translation_seccomp_context_localhost_allowed_annotation_missing {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_annotation}
    results := violation with input as inp
    count(results) == 1
}

# Create Review Object
get_object(annotations, podcontext, containers, initcontainers) = {"object": {
    "metadata": {
        "name": "nginx",
        "annotations": annotations,
    },
    "spec": {
        "containers": containers,
        "initContainers": initcontainers,
        "securityContext": podcontext,
    },
}}

# Test Containers
single_container = [{
    "name": "nginx",
    "image": "nginx",
}]

multiple_containers = [
    {
        "name": "nginx",
        "image": "nginx",
    },
    {
        "name": "nginx2",
        "image": "nginx",
    },
]

single_container_sc = [{
    "name": "nginx",
    "image": "nginx",
    "securityContext": context_runtimedefault,
}]

multiple_containers_sc = [
    {
        "name": "nginx",
        "image": "nginx",
        "securityContext": context_runtimedefault,
    },
    {
        "name": "nginx2",
        "image": "nginx",
        "securityContext": context_runtimedefault,
    },
]

multiple_containers_sc_mixed = [
    {
        "name": "nginx",
        "image": "nginx",
        "securityContext": context_runtimedefault,
    },
    {
        "name": "nginx2",
        "image": "nginx",
        "securityContext": context_localhost,
    },
]

multiple_containers_sc_missing = [
    {
        "name": "nginx",
        "image": "nginx",
        "securityContext": context_runtimedefault,
    },
    {
        "name": "nginx2",
        "image": "nginx",
    },
]

# Test Annotations
pod_annotation = {"seccomp.security.alpha.kubernetes.io/pod": "runtime/default"}

pod_annotation_unconfined = {"seccomp.security.alpha.kubernetes.io/pod": "unconfined"}

pod_container_annotations = {
    "seccomp.security.alpha.kubernetes.io/pod": "runtime/default",
    "container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default",
}

pod_container_annotations_mixed = {
    "seccomp.security.alpha.kubernetes.io/pod": "runtime/default",
    "container.seccomp.security.alpha.kubernetes.io/nginx": "localhost/profile.json",
}

pod_container_annotations_mixed_rev = {
    "seccomp.security.alpha.kubernetes.io/pod": "localhost/profile.json",
    "container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default",
}

container_annotation = {"container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default"}

container_annotation_unconfined = {"container.seccomp.security.alpha.kubernetes.io/nginx": "unconfined"}

container_annotations = {
    "container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default",
    "container.seccomp.security.alpha.kubernetes.io/nginx2": "runtime/default",
}

container_annotations_mixed = {
    "container.seccomp.security.alpha.kubernetes.io/nginx": "runtime/default",
    "container.seccomp.security.alpha.kubernetes.io/nginx2": "localhost/profile.json",
}

# Test securityContexts
context_localhost = {"seccompProfile": {"type": "Localhost", "localhostProfile": "profile.json"}}

context_localhost1 = {"seccompProfile": {"type": "Localhost", "localhostProfile": "profile1.json"}}

context_runtimedefault = {"seccompProfile": {"type": "RuntimeDefault"}}

context_unconfined = {"seccompProfile": {"type": "Unconfined"}}

# Test Parameters
input_parameters_empty = {"allowedProfiles": []}

input_parameters_wildcard = {"allowedProfiles": ["*"]}

input_parameters_localhost_wildcard = {"allowedProfiles": ["localhost/*"]}

input_parameters_localhost_wildcard_both = {"allowedProfiles": ["localhost/*"], "allowedLocalhostFiles": ["*"]}

input_parameter_in_list = {"allowedProfiles": [
    "runtime/default",
    "RuntimeDefault",
]}

input_parameters_in_list = {
    "allowedProfiles": [
        "runtime/default",
        "RuntimeDefault",
        "docker/default",
        "Localhost",
    ],
    "allowedLocalhostFiles": ["profile.json"],
}

input_parameters_not_in_list = {"allowedProfiles": [
    "unconfined",
    "Unconfined",
]}

input_parameters_exempt = {
    "exemptImages": ["nginx"],
    "allowedProfiles": ["unconfined"],
}

input_parameters_annotation = {"allowedProfiles": [
    "runtime/default",
    "docker/default",
    "localhost/profile1.json",
    "localhost/profile2.json",
    "unconfined",
]}

input_parameters_sc = {
    "allowedProfiles": [
        "RuntimeDefault",
        "Localhost",
        "Unconfined",
    ],
    "allowedLocalhostFiles": [
        "profile1.json",
        "profile2.json",
    ],
}

input_parameters_sc_localhost_wildcard_file = {
    "allowedProfiles": ["Localhost"],
    "allowedLocalhostFiles": ["*"],
}

input_parameters_sc_localhost_no_file = {"allowedProfiles": ["Localhost"]}

allowed_full_translated = {
    "Localhost", "localhost/profile1.json", "localhost/profile2.json",
    "RuntimeDefault", "docker/default", "runtime/default",
    "Unconfined", "unconfined",
}

allowed_full_translated_annotation_style = {
    "runtime/default",
    "docker/default",
    "localhost/profile1.json",
    "localhost/profile2.json",
    "unconfined",
}
