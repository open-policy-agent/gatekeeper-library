package k8spspflexvolumes

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
	# spec.volumes field is immutable.
	not is_update(input.review)
	some volume in input_flexvolumes
	not input_flexvolumes_allowed(volume)

	msg := sprintf(
		"FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v",
		[volume, input.review.object.metadata.name, input.parameters.allowedFlexVolumes],
	)
}

input_flexvolumes_allowed(volume) if {
	input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
}

input_flexvolumes contains volume if {
	some volume in input.review.object.spec.volumes
	"flexVolume" in object.keys(volume)
}
