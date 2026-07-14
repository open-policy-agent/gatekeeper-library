package k8spspflexvolumes

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
    # spec.volumes field is immutable.
    not is_update(input.review)

    volume := input_flexvolumes[_]
    not input_flexvolumes_allowed(volume)
    msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.review.object.metadata.name, input.parameters.allowedFlexVolumes])
}

input_flexvolumes_allowed(volume) if {
    input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
}

input_flexvolumes contains v if {
    v := input.review.object.spec.volumes[_]
    has_field(v, "flexVolume")
}

# has_field returns whether an object has a field
has_field(object, field) if {
    object[field]
}
