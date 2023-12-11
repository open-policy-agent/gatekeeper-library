package k8spspforbiddensysctls

test_input_sysctls_forbidden_all {
    inp := { "review": input_review, "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 2
}

test_input_sysctls_forbidden_in_list {
    inp := { "review": input_review, "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_sysctls_forbidden_in_list_mixed {
    inp := { "review": input_review, "parameters": input_parameters_one_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_sysctls_forbidden_not_in_list {
    inp := { "review": input_review, "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_forbidden_in_list_wildcard {
    inp := { "review": input_review, "parameters": input_parameters_in_list_wildcard}
    results := violation with input as inp
    count(results) == 2
}

test_input_sysctls_forbidden_in_list_wildcard_mixed {
    inp := { "review": input_review, "parameters": input_parameters_one_in_list_wildcard}
    results := violation with input as inp
    count(results) == 1
}

test_input_sysctls_forbidden_not_in_list_wildcard {
    inp := { "review": input_review, "parameters": input_parameters_not_in_list_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_empty_forbidden {
    inp := { "review": input_review, "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccontext_empty_wildcard {
    inp := { "review": input_review_seccontext_empty, "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_empty_wildcard {
    inp := { "review": input_review_sysctls_empty, "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccontext_null_wildcard {
    inp := { "review": input_review_seccontext_null, "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccontext_empty_empty_forbidden {
    inp := { "review": input_review_seccontext_empty, "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_empty_empty_forbidden {
    inp := { "review": input_review_sysctls_empty, "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 0
}

test_input_seccontext_null_empty_forbidden {
    inp := { "review": input_review_seccontext_null, "parameters": input_parameters_empty}
    results := violation with input as inp
    count(results) == 0
}

test_input_init_sysctls_forbidden_all {
    inp := { "review": input_init_review, "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 2
}

test_input_init_sysctls_forbidden_in_list {
    inp := { "review": input_init_review, "parameters": input_parameters_in_list}
    results := violation with input as inp
    count(results) == 2
}

test_input_init_sysctls_forbidden_in_list_mixed {
    inp := { "review": input_init_review, "parameters": input_parameters_one_in_list}
    results := violation with input as inp
    count(results) == 1
}

test_input_init_sysctls_forbidden_not_in_list {
    inp := { "review": input_init_review, "parameters": input_parameters_not_in_list}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_allowed_all {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_allowed_all}
    results := violation with input as inp
    count(results) == 0
}

# Empty allowedSysctls means none are allowed.
# This is in contrast to unspecified allowedSysctls which does not
# place any restrictions by itself.
test_input_sysctls_allowed_empty {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_allowed_empty}
    results := violation with input as inp
    count(results) == 2
}

test_input_sysctls_allowed_exact {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_allowed_exact}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_allowed_wildcards {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_allowed_wildcards}
    results := violation with input as inp
    count(results) == 0
}

test_input_sysctls_some_allowed_exact {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_some_allowed_exact}
    results := violation with input as inp
    count(results) == 1
}

test_input_sysctls_some_allowed_wildcards {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_some_allowed_wildcards}
    results := violation with input as inp
    count(results) == 1
}

test_input_sysctls_allowed_and_forbidden {
    inp := { "review": input_review, "parameters": input_parameters_sysctls_allowed_and_forbidden}
    results := violation with input as inp
    count(results) == 2
}

test_update {
    inp := { "review": object.union(input_review, {"operation": "UPDATE"}), "parameters": input_parameters_wildcard}
    results := violation with input as inp
    count(results) == 0
}

input_review = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": {
                "name": "nginx",
                "image": "nginx"
            },
            "securityContext": {
                "sysctls": [
                    {
                        "name": "kernel.shm_rmid_forced",
                        "value": "0"
                    },
                    {
                        "name": "net.core.somaxconn",
                        "value": "1024"
                    }
                ]
            }
        }
    }
}

input_init_review = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "initContainers": {
                "name": "nginx",
                "image": "nginx"
            },
            "securityContext": {
                "sysctls": [
                    {
                        "name": "kernel.shm_rmid_forced",
                        "value": "0"
                    },
                    {
                        "name": "net.core.somaxconn",
                        "value": "1024"
                    }
                ]
            }
        }
    }
}

input_review_seccontext_empty = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": {
                "name": "nginx",
                "image": "nginx",
            },
            "securityContext": {
            }
        }
    }
}

input_review_sysctls_empty = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": {
                "name": "nginx",
                "image": "nginx",
            },
            "securityContext": {
                "sysctls": []
            }
        }
    }
}

input_review_seccontext_null = {
    "object": {
        "metadata": {
            "name": "nginx"
        },
        "spec": {
            "containers": {
                "name": "nginx",
                "image": "nginx",
            }
        }
    }
}

input_parameters_wildcard = {
    "forbiddenSysctls": [
        "*"
    ]
}

input_parameters_in_list = {
    "forbiddenSysctls": [
        "kernel.shm_rmid_forced",
        "net.core.somaxconn"
    ]
}

input_parameters_one_in_list = {
    "forbiddenSysctls": [
        "kernel.shm_rmid_forced"
    ]
}

input_parameters_not_in_list = {
    "forbiddenSysctls": [
        "kernel.msgmax"
    ]
}

input_parameters_in_list_wildcard = {
    "forbiddenSysctls": [
        "kernel.*",
        "net.core*"
    ]
}

input_parameters_one_in_list_wildcard = {
    "forbiddenSysctls": [
        "kernel.*"
    ]
}

input_parameters_not_in_list_wildcard = {
    "forbiddenSysctls": [
        "kernel.msg*"
    ]
}

input_parameters_empty = {
    "forbiddenSysctls": []
}

input_parameters_sysctls_allowed_all = {
    "allowedSysctls": ["*"]
}

input_parameters_sysctls_allowed_empty = {
    "allowedSysctls": []
}

input_parameters_sysctls_allowed_wildcards = {
    "allowedSysctls": [
        "kernel.*",
        "net.*"
    ]
}

input_parameters_sysctls_allowed_exact = {
    "allowedSysctls": [
        "kernel.shm_rmid_forced",
        "net.core.somaxconn"
    ]
}

input_parameters_sysctls_some_allowed_exact = {
    "allowedSysctls": [
        "net.core.somaxconn"
    ]
}

input_parameters_sysctls_some_allowed_wildcards = {
    "allowedSysctls": [
        "net.*"
    ]
}

input_parameters_sysctls_allowed_and_forbidden = {
    "allowedSysctls": [
        "kernel.shm_rmid_forced",
        "net.core.somaxconn"
    ],
    "forbiddenSysctls": [
        "kernel.shm_rmid_forced",
        "net.core.somaxconn"
    ]
}
