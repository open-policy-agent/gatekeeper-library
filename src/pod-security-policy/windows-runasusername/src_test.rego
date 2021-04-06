package windowsrunasusername

test_no_usernames_no_node_selector {
    input := {
        "review": make_review(null, [ctr("ctr1", null)], null, null),
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 0
}

test_no_usernames_windows_node_selector {
    input := {
        "review": make_review(null, [ctr("ctr1", null)], null, windowsNodeSelector),
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 0
}

test_disallowed_pod_username_but_no_node_selector {
    input := {
        "review": make_review("admin", [ctr("ctr1", null)], null, null), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 0
}

test_disallowed_pod_username1 {
    input := {
        "review": make_review("admin", [ctr("ctr1", null)], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 1
}

test_disallowed_pod_username2 {
    input := {
        "review": make_review("SYSTEM", [ctr("ctr1", null)], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 1
}

test_disallowed_pod_username_but_allowed_container_username {
    input := {
        "review": make_review("SYSTEM", [ctr("ctr1", "user")], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 0
}

test_disallowed_container_username_no_pod_username {
    input := {
        "review": make_review(null, [ctr("ctr1", "user")], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 0
}

test_disallowed_container_username_allowed_pod_username {
    input := {
        "review": make_review("user", [ctr("ctr1", "SYSTEM")], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 1
}

test_multiple_disallowed_container_usernames1 {
    input := {
        "review": make_review("user", [ctr("ctr1", "SYSTEM"), ctr("ctr2", "admin"), ctr("ctr3", null)], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 2
}

test_multiple_disallowed_container_usernames2 {
    input := {
        "review": make_review(null, [ctr("ctr1", "SYSTEM"), ctr("ctr2", "admin"), ctr("ctr3", null)], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 2
}

test_multiple_disallowed_container_usernames2 {
    input := {
        "review": make_review("admin", [ctr("ctr1", "SYSTEM"), ctr("ctr2", "admin"), ctr("ctr3", null)], null, windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 3
}

test_disallowed_initcontainer_usernames {
    input := {
        "review": make_review("admin", [ctr("ctr1", "user")], [ctr("initCtr1", null), ctr("initCtr2", "SYSTEM")], windowsNodeSelector), 
        "parameters": {"disallowedUserNames": ["admin", "SYSTEM"]}
    }
    results := violation with input as input
    count(results) == 2
}

# make_review is a helper function to make pod specs for unit testing.

make_review(podRunAsUserName, containers, initContainers, nodeSelector) = out {
    pod_sercurity_context_obj := obj_if_exists("securityContext", windows_options_with_runasusername(podRunAsUserName))
    containers_obj := obj_if_exists("containers", containers)
    init_containers_obj := obj_if_exists("initContainers", initContainers)
    node_selector_obj := obj_if_exists("nodeSelector", nodeSelector)
    out = {
        "kind": {
            "kind": "Pod"
        },
        "metadata": {
            "name": "test-pod"
        },
        "object": {
            "spec": object.union(object.union(object.union(pod_sercurity_context_obj, containers_obj), init_containers_obj), node_selector_obj)
        }
    }
}

windowsNodeSelector = out {
    out = {
        "kubernetes.io/os": "windows"
    }
}

windows_options_with_runasusername(name) = out {
    not is_null(name)
    out = {
            "windowsOptions": {
                "runAsUserName": name
            }
        }
}
windows_options_with_runasusername(name) = out {
    is_null(name)
    out = null
}

ctr(name, runAsUserName) = out {
    name_obj := { "name": name }
    security_context_obj := obj_if_exists("securityContext", windows_options_with_runasusername(runAsUserName))
    out = object.union(name_obj, security_context_obj)
}

obj_if_exists(key, val) = out {
    not is_null(val)
    out := { key: val }
}
obj_if_exists(key, val) = out {
    is_null(val)
    out := {}
}