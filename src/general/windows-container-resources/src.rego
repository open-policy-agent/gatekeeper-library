package k8swindowscontainerresources

violation[{"msg":msg}] {
    is_windows_pod
    container := input_containers[_]
    not has_limits(container)
    msg := sprintf("Container <%v> has missing resource limits", [container.name])
}

violation[{"msg":msg}] {
    is_windows_pod
    container := input_containers[v]
    requests_do_not_match_limits(container)
    msg := sprintf("Container <%v> sets reource requests that do not match limits", [container.name])
}

is_windows_pod {
    ns := input.review.object.spec.nodeSelector
    ns["kubernetes.io/os"] == "windows"
}

has_limits(c) {
    get_cpu_limit(c)
    get_mem_limit(c)
}

requests_do_not_match_limits(c) {
    # Tests that cpu requests match limits if specified
    r := get_cpu_request(c)
    l := get_cpu_limit(c)
    r != null
    l != null
    r != l
}
requests_do_not_match_limits(c) {
    # Tests that mem requests match limits if specified
    r := get_mem_request(c)
    l := get_mem_limit(c)
    r != null
    l != null
    r != l
}

get_cpu_limit(c) = out {
    out := c.resources.limits.cpu
}

get_cpu_request(c) = out {
    out := c.resources.requests.cpu
}

get_mem_limit(c) = out {
    out := c.resources.limits.memory
}

get_mem_request(c) = out {
    out := c.resources.requests.memory
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}