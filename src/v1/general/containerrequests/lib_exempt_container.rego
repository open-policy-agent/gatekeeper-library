package lib.exempt_container

import rego.v1

is_exempt(container) if {
	some exemption in input.parameters.exemptImages
	_matches_exemption(container.image, exemption)
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
