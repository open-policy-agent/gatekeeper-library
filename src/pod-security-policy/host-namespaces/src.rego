package k8spsphostnamespace

import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    containers := input_containers[_]
    not is_exempt(containers)
    input_share_hostnamespace(input.review.object)
    msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
}

input_share_hostnamespace(o) {
    o.spec.hostPID
}
input_share_hostnamespace(o) {
    o.spec.hostIPC
}
input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
