package k8spspseccomp

# securityContext based seccomp with containers

test_input_seccomp_allowed_in_list {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_allowed_all {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
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

test_input_seccomp_containers_allowed_in_list {
    inp := {"review": get_object({}, {}, multiple_containers_sc, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_containers_allowed_in_list_localhost {
    inp := {"review": get_object({}, {}, single_container_sc_localhost, {}), "parameters": input_parameters_in_list_locahost_file}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_containers_allowed_in_list_multiple {
    inp := {"review": get_object({}, {}, multiple_containers_sc_mixed, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_not_allowed_not_in_list {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_empty_parameters {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 1
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

test_input_seccomp_container_not_allowed_not_in_list {
    inp := {"review": get_object({}, {}, single_container_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_seccomp_containers_not_allowed_not_in_list {
    inp := {"review": get_object({}, {}, multiple_containers_sc, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_not_allowed_multiple_not_configured {
    inp := {"review": get_object({}, {}, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 2
}

# securityContext based seccomp with pod

test_input_seccomp_pod_multiple_allowed_all {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_localhost_allowed_both_wildcard_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_localhost_wildcard_both}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers_sc_missing, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container_both_allowed {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers_sc_missing, {}), "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_container_mixed_not_allowed_but_exempt {
    inp := {"review": get_object({}, context_runtimedefault, single_container, {}), "parameters": input_parameters_exempt}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_multiple_allowed_in_list {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameter_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_localhost_allowed_wildcard_file {
    inp := {"review": get_object({}, context_localhost, single_container, {}), "parameters": input_parameters_sc_localhost_wildcard_file}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccomp_pod_multiple_empty_parameters {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_pod_multiple_not_allowed_not_in_list {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_seccomp_pod_container_not_allowed {
    inp := {"review": get_object({}, context_runtimedefault, multiple_containers_sc_missing, {}), "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 2
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
    inp := {"review": get_object({}, context_runtimedefault, {}, multiple_containers_sc_missing), "parameters": input_parameters_in_list}
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

# Localhost seccomp profile build

test_translation_seccomp_allowed_context_localhost_wildcard_file {
    inp := {"parameters": input_parameters_localhost_wildcard_both}
    output := get_allowed_profiles with input as inp
    output == {{"type": "Localhost", "localHostProfile": "*"}}
}

test_translation_seccomp_allowed_context_localhost_no_file {
    inp := {"parameters": input_parameters_sc_localhost_no_file}
    output := get_allowed_profiles with input as inp
    output == {{"localHostProfile": "", "type": "Localhost"}}
}

test_translation_seccomp_allowed_context_localhost_with_file {
    inp := {"parameters": input_parameters_sc_localhost_with_file}
    output := get_allowed_profiles with input as inp
    output == {{"type": "Localhost", "localHostProfile": "profile.json"}}
}

test_translation_seccomp_allowed_context_mixed {
    inp := {"parameters": input_parameters_in_list}
    output := get_allowed_profiles with input as inp
    output == {{"type": "Localhost", "localHostProfile": "profile.json"}, {"type": "RuntimeDefault"}}
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

single_container_sc_localhost = [{
    "name": "nginx",
    "image": "nginx",
    "securityContext": context_localhost,
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

# Test securityContexts
context_localhost = {"seccompProfile": {"type": "Localhost", "localhostProfile": "profile.json"}}

context_runtimedefault = {"seccompProfile": {"type": "RuntimeDefault"}}

# Test Parameters
input_parameters_empty = {"allowedProfiles": []}

input_parameters_wildcard = {"allowedProfiles": ["*"]}

input_parameter_in_list = {"allowedProfiles": [
    "RuntimeDefault",
]}

input_parameters_in_list = {
    "allowedProfiles": [
        "RuntimeDefault",
        "Localhost",
    ],
    "allowedLocalhostFiles": ["profile.json"],
}

input_parameters_in_list_locahost_file = {
    "allowedProfiles": [
        "Localhost",
    ],
    "allowedLocalhostFiles": ["profile.json"],
}

input_parameters_not_in_list = {"allowedProfiles": [
    "Unconfined",
]}

input_parameters_exempt = {
    "exemptImages": ["nginx"],
    "allowedProfiles": ["Unconfined"],
}

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

input_parameters_sc_localhost_no_file = {
    "allowedProfiles": ["Localhost"],
}

input_parameters_localhost_wildcard_both = {"allowedProfiles": ["Localhost"], "allowedLocalhostFiles": ["*"]}

input_parameters_sc_localhost_wildcard_file = {
    "allowedProfiles": ["Localhost"],
    "allowedLocalhostFiles": ["*"],
}

input_parameters_sc_localhost_with_file = {"allowedProfiles": ["Localhost"], "allowedLocalhostFiles": ["profile.json"]}