package k8srequiredtimeoutseconds


violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    probe := input.parameters.probes[_]
    probe_timeout_is_missing(container, probe)
    msg := get_violation_message(container, input.review, probe)
}

probe_timeout_is_missing(ctr, probe) = true {
    ctr[probe]
    not ctr[probe].timeoutSeconds
}

get_violation_message(container, review, probe) = msg {
    msg := sprintf("Container <%v> in your <%v> <%v> has no <%v>", [container.name, review.kind.kind, review.object.metadata.name, probe])
}

