package k8sblockendpointeditdefaultrole

test_input_no_endpoints_edit_role_allow {
    inp := { "review": input_review_withoutendpoints }
    results := violation with input as inp
    count(results) == 0
}

test_input_endpoints_create_role_not_allow {
    inp := { "review": input_review_with_endpoints_create }
    results := violation with input as inp
    count(results) == 1
}

test_input_endpoints_update_role_not_allow {
    inp := { "review": input_review_with_endpoints_update }
    results := violation with input as inp
    count(results) == 1
}

test_input_endpoints_patch_role_not_allow {
    inp := { "review": input_review_with_endpoints_patch }
    results := violation with input as inp
    count(results) == 1
}

test_input_endpoints_delete_role_allow {
    inp := { "review": input_review_with_endpoints_delete }
    results := violation with input as inp
    count(results) == 0
}

input_review_withoutendpoints() = {
    "object": {
        "metadata":{
            "annotations":{
                "rbac.authorization.kubernetes.io/autoupdate": "false"
            },
            "name": "system:aggregate-to-edit"
        },
        "rules": [
            input_rule(["pods"], ["create"]),
            input_rule(["services"], ["delete"])
        ]
    }
}

input_review_with_endpoints_create() = {
    "object": {
        "metadata":{
            "annotations":{
                "rbac.authorization.kubernetes.io/autoupdate": "false"
            },
            "name": "system:aggregate-to-edit"
        },
        "rules": [
            input_rule(["pods", "endpoints"], ["create"]),
            input_rule(["services"], ["delete"])
        ]
    }
}

input_review_with_endpoints_update() = {
    "object": {
        "metadata":{
            "annotations":{
                "rbac.authorization.kubernetes.io/autoupdate": "false"
            },
            "name": "system:aggregate-to-edit"
        },
        "rules": [
            input_rule(["pods", "endpoints"], ["update"]),
            input_rule(["services"], ["delete"])
        ]
    }
}

input_review_with_endpoints_patch() = {
    "object": {
        "metadata":{
            "annotations":{
                "rbac.authorization.kubernetes.io/autoupdate": "false"
            },
            "name": "system:aggregate-to-edit"
        },
        "rules": [
            input_rule(["pods", "endpoints"], ["patch"]),
            input_rule(["services"], ["delete"])
        ]
    }
}

input_review_with_endpoints_delete() = {
    "object": {
        "metadata":{
            "annotations":{
                "rbac.authorization.kubernetes.io/autoupdate": "false"
            },
            "name": "system:aggregate-to-edit"
        },
        "rules": [
            input_rule(["pods"], ["create"]),
            input_rule(["services", "endpoints"], ["delete"])
        ]
    }
}

input_rule(resources,verbs) = {
    "apiGroups": [""],
    "resources": resources,
    "verbs": verbs
}
