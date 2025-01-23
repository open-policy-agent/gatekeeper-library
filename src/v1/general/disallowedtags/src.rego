package k8sdisallowedtags

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	some container in input_containers
	tags := [tag_with_prefix |
		some tag in input.parameters.tags
		tag_with_prefix := concat(":", ["", tag])
	]
	strings.any_suffix_match(container.image, tags)
	msg := sprintf(
		"container <%v> uses a disallowed tag <%v>; disallowed tags are %v",
		[container.name, container.image, input.parameters.tags],
	)
}

violation contains {"msg": msg} if {
	some container in input_containers
	not contains(container.image, ":")
	msg := sprintf("container <%v> didn't specify an image tag <%v>", [container.name, container.image])
}

input_containers contains container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)
}
