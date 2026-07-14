package k8spsphostnetworkingports

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    # spec.hostNetwork field is immutable.
    not is_update(input.review)

    input_share_hostnetwork(input.review.object)
    msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.review.object.metadata.name, input.parameters])
}

input_share_hostnetwork(o) if {
    not input.parameters.hostNetwork
    o.spec.hostNetwork
}

input_share_hostnetwork(_) if {
    hostPort := input_containers[_].ports[_].hostPort
    hostPort < input.parameters.min
}

input_share_hostnetwork(_) if {
    hostPort := input_containers[_].ports[_].hostPort
    hostPort > input.parameters.max
}

input_containers contains c if {
    c := input.review.object.spec.containers[_]
    not is_exempt(c)
}

input_containers contains c if {
    c := input.review.object.spec.initContainers[_]
    not is_exempt(c)
}

input_containers contains c if {
    c := input.review.object.spec.ephemeralContainers[_]
    not is_exempt(c)
}
