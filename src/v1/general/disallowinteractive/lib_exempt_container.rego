package lib.exempt_container

import rego.v1

is_exempt(container) if {
	exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
	img := container.image
	some exemption in exempt_images
	_matches_exemption(img, exemption)
}

_matches_exemption(img, exemption) if {
	not endswith(exemption, "*")
	exemption == img
}

_matches_exemption(img, exemption) if {
	endswith(exemption, "*")
	prefix := trim_suffix(exemption, "*")
	startswith(img, prefix)
}
