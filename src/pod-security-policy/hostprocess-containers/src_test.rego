package k8spsphostprocess

test_empty_spec {
    input := { "review": make_review(null, null, null) }
    results := violation with input as input
    count(results) == 0
}

test_pod_hostprocess_null_no_hostprocess_containers {
    input := { "review": make_review(null, [ctr("ctr1", null), ctr("ctr2", false)], [ctr("init1", null), ctr("init2", false)]) }
    results := violation with input as input
    count(results) == 0
}

test_pod_hostprocess_false_no_hostprocess_containers {
    input := { "review": make_review(false, [ctr("ctr1", null), ctr("ctr2", false)], [ctr("init1", null), ctr("init2", false)]) }
    results := violation with input as input
    count(results) == 0
}

test_pod_hostprocess_null_some_hostprocess_containers {
    input := { "review": make_review(null, [ctr("ctr1", null), ctr("ctr2", false), ctr("ctr3", true)], [ctr("init1", null), ctr("init2", false), ctr("init3", true)]) }
    results := violation with input as input
    count(results) == 2
}

test_pod_hostprocess_false_some_hostprocess_containers {
    input := { "review": make_review(false, [ctr("ctr1", null), ctr("ctr2", false), ctr("ctr3", true)], [ctr("init1", null), ctr("init2", false), ctr("init3", true)]) }
    results := violation with input as input
    count(results) == 2
}


test_pod_hostprocess_true_no_containers_set_hostprocess { input := { "review": make_review(true, [ctr("ctr1", null)], [ctr("init1", null)]) }
    results := violation with input as input
    count(results) == 2
}

test_pod_hostprocess_true_containers_set_hostprocess_false {
    input := { "review": make_review(true, [ctr("ctr1", false)], [ctr("init1", false)]) }
    results := violation with input as input
    count(results) == 0
}

test_pod_hostprocess_true_containers_set_hostprocess_true {
    input := { "review": make_review(true, [ctr("ctr1", true)], [ctr("init1", true)]) }
    results := violation with input as input
    count(results) == 2
}

test_pod_hostprocess_true_some_containers_set_hostprocess_true {
    input := { "review": make_review(true, [ctr("ctr1", null), ctr("ctr2", false), ctr("ctr3", true)], [ctr("init1", null), ctr("init2", false), ctr("init3", true)]) }
    results := violation with input as input
    count(results) == 4
}

make_review(pod_is_hostprocess, containers, init_containers) = out {

    pod_security_context_obj := obj_if_exists("securityContext", windows_options_with_hostprocess(pod_is_hostprocess))
    container_obj := obj_if_exists("containers", containers)
    init_containers_obj := obj_if_exists("initContainers", init_containers)
    out = {
        "object": {
            "spec": object.union(object.union(pod_security_context_obj, container_obj), init_containers_obj)
        }
    }
}

windows_options_with_hostprocess(is_hostprocess) = out {
    not is_null(is_hostprocess)
    out = {
        "windowsOptions": {
            "hostProcess": is_hostprocess
        }
    }
}

windows_options_with_hostprocess(is_hostprocess) = out {
    is_null(is_hostprocess)
    out = null
}

ctr(name, is_hostprocess) = out {
    name_obj = { "name": name }
    security_context_obj := obj_if_exists("securityContext", windows_options_with_hostprocess(is_hostprocess))
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
