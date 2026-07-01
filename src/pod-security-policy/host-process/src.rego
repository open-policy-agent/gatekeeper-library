package k8spsphostprocess

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    # spec.securityContext.windowsOptions.hostProcess field is immutable.
    not is_update(input.review)

    # Check pod-level securityContext
    input.review.object.spec.securityContext.windowsOptions.hostProcess == true
    msg := sprintf("HostProcess is not allowed at pod level: %v", [input.review.object.metadata.name])
}

violation contains {"msg": msg, "details": {}} if {
    # spec.containers.securityContext.windowsOptions.hostProcess field is immutable.
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    c.securityContext.windowsOptions.hostProcess == true
    msg := sprintf("HostProcess container is not allowed: %v, securityContext.windowsOptions.hostProcess: true", [c.name])
}

input_containers contains c if {
    c := input.review.object.spec.containers[_]
}

input_containers contains c if {
    c := input.review.object.spec.initContainers[_]
}

input_containers contains c if {
    c := input.review.object.spec.ephemeralContainers[_]
}
