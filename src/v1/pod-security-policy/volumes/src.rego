package k8spspvolumetypes

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
	# spec.volumes field is immutable.
	not is_update(input.review)
	some field in {x | input.review.object.spec.volumes[_][x]; x != "name"}
	not input_volume_type_allowed(field)

	msg := sprintf(
		"The volume type %v is not allowed, pod: %v. Allowed volume types: %v",
		[field, input.review.object.metadata.name, input.parameters.volumes],
	)
}

# * may be used to allow all volume types
input_volume_type_allowed(_) if "*" in input.parameters.volumes

input_volume_type_allowed(field) if field in input.parameters.volumes
