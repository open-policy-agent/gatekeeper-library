package k8spspvolumetypes

import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    volume_fields := {x | mounted_volumes[_][x]; x != "name"}
    field := volume_fields[_]
    not input_volume_type_allowed(field)
    msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.review.object.metadata.name, input.parameters.volumes])
}

# * may be used to allow all volume types
input_volume_type_allowed(field) {
    input.parameters.volumes[_] == "*"
}

mounted_volumes[volumes] {
    container := input_containers[_]
    not is_exempt(container)
    volumeNames := {x | x := container.volumeMounts[_].name}
    volumes := {x | x := input.review.object.spec.volumes[_]; x.name == volumeNames[_]}[_]
}

input_volume_type_allowed(field) {
    field == input.parameters.volumes[_]
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}