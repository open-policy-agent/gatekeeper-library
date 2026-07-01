package lib.exempt_container

import future.keywords.contains
import future.keywords.if

is_exempt(container) if {
    exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
    img := container.image
    exemption := exempt_images[_]
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
