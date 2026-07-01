package k8spspfsgroup

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
    # spec.securityContext.fsGroup field is immutable.
    not is_update(input.review)
    has_field(input.parameters, "rule")
    spec := input.review.object.spec
    not input_fsGroup_allowed(spec)
    msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.review.object.metadata.name, input.parameters])
}

input_fsGroup_allowed(_) if {
    # RunAsAny - No range is required. Allows any fsGroup ID to be specified.
    input.parameters.rule == "RunAsAny"
}

input_fsGroup_allowed(spec) if {
    # MustRunAs - Validates pod spec fsgroup against all ranges
    input.parameters.rule == "MustRunAs"
    fg := spec.securityContext.fsGroup
    count(input.parameters.ranges) > 0
    range := input.parameters.ranges[_]
    value_within_range(range, fg)
}

input_fsGroup_allowed(spec) if {
    # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
    input.parameters.rule == "MayRunAs"
    not has_field(spec, "securityContext")
}

input_fsGroup_allowed(spec) if {
    # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
    input.parameters.rule == "MayRunAs"
    not spec.securityContext.fsGroup
}

input_fsGroup_allowed(spec) if {
    # MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
    input.parameters.rule == "MayRunAs"
    fg := spec.securityContext.fsGroup
    count(input.parameters.ranges) > 0
    range := input.parameters.ranges[_]
    value_within_range(range, fg)
}

value_within_range(range, value) if {
    range.min <= value
    range.max >= value
}

# has_field returns whether an object has a field
has_field(object, field) if {
    object[field]
}
