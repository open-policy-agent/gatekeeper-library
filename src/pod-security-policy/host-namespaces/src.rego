package k8spsphostnamespace

import data.lib.exclude_update.is_update

violation[{"msg": msg, "details": {}}] {
    # spec.hostPID and spec.hostIPC fields are immutable.
    not is_update(input.review)

    input_share_hostnamespace(input.review.object)
    msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
}

input_share_hostnamespace(o) {
    o.spec.hostPID
}
input_share_hostnamespace(o) {
    o.spec.hostIPC
}
