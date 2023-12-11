package k8spspvolumetypes

import data.lib.exclude_update.is_update

violation[{"msg": msg, "details": {}}] {
    # spec.volumes field is immutable.
    not is_update(input.review)

    volume_fields := {x | input.review.object.spec.volumes[_][x]; x != "name"}
    field := volume_fields[_]
    not input_volume_type_allowed(field)
    msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.review.object.metadata.name, input.parameters.volumes])
}

# * may be used to allow all volume types
input_volume_type_allowed(_) {
    input.parameters.volumes[_] == "*"
}

input_volume_type_allowed(field) {
    field == input.parameters.volumes[_]
}
