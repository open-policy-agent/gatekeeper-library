package k8spsphostprocess

violation[{"msg": msg}] {
    c := input_containers[_]
    is_hostprocess(c)
    msg := sprintf("HostProcess container is not allowed: %v", [c.name])
}

# returns true if hostProcess is set to true for container
is_hostprocess(c) = true {
    c.securityContext.windowsOptions.hostProcess == true
}

# returns true if hostProcess is not specified for container AND is set to true on pod
is_hostprocess(c) = true {
    not sets_hostprocess(c)
    input.review.object.spec.securityContext.windowsOptions.hostProcess == true
}

# returns true if hostProcess is set for container
sets_hostprocess(c) {
    c.securityContext.windowsOptions.hostProcess != null
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
