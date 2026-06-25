package k8spsphostnamespace

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
    # spec.hostPID and spec.hostIPC fields are immutable.
    not is_update(input.review)

    input_share_hostnamespace(input.review.object)
    msg := sprintf("Sharing the host namespace is not allowed: %v", [input.review.object.metadata.name])
}

input_share_hostnamespace(o) if {
    o.spec.hostPID
}

input_share_hostnamespace(o) if {
    o.spec.hostIPC
}
