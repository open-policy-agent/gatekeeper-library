package k8spsphostnamespace

import data.lib.exclude_update_patch.is_update_or_patch

violation[{"msg": msg, "details": {}}] {
    # spec.hostPID and spec.hostIPC fields are immutable.
    not is_update_or_patch(input.review)

    input_share_hostnamespace(input.review.object)
    msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
}

input_share_hostnamespace(o) {
    o.spec.hostPID
}
input_share_hostnamespace(o) {
    o.spec.hostIPC
}
