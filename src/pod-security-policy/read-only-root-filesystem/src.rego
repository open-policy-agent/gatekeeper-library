package k8spspreadonlyrootfilesystem

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    # spec.containers.readOnlyRootFilesystem field is immutable.
    not is_update(input.review)

    c := input_containers[_]
    not is_exempt(c)
    input_read_only_root_fs(c)
    msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
}

input_read_only_root_fs(c) if {
    not has_field(c, "securityContext")
}

input_read_only_root_fs(c) if {
    not c.securityContext.readOnlyRootFilesystem == true
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

# has_field returns whether an object has a field
has_field(object, field) if {
    object[field]
}
