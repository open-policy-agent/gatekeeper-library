package k8sallowedreposv2

import rego.v1

violation contains {"msg": msg} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not image_matches(container.image, input.parameters.allowedImages)

	msg := sprintf(
		"%s <%v> has an invalid image <%v>, allowed images are %v",
		[trim_suffix(type, "s"), container.name, container.image, input.parameters.allowedImages],
	)
}

image_matches(image, images) if {
	some i_image in images # Iterate through all images in the allowed list
	not endswith(i_image, "*") # Check for exact match if the image does not end with *
	i_image == image
}

image_matches(image, images) if {
	some i_image in images # Iterate through all images in the allowed list
	endswith(i_image, "*") # Check for prefix match if the image ends with *
	prefix := trim_suffix(i_image, "*")
	startswith(image, prefix)
}
