package k8spspvolumetypes

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
    # spec.volumes field is immutable.
    not is_update(input.review)

    volume_fields := {x | input.review.object.spec.volumes[_][x]; x != "name"}
    field := volume_fields[_]
    not input_volume_type_allowed(field)
    msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.review.object.metadata.name, input.parameters.volumes])
}

# * may be used to allow all volume types
input_volume_type_allowed(_) if {
    input.parameters.volumes[_] == "*"
}

input_volume_type_allowed(field) if {
    field == input.parameters.volumes[_]
}
