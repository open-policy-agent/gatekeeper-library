package lib.exempt_container

is_exempt(container) {
    exempt_image_prefixes := object.get(object.get(input, "parameters", {}), "exemptImagePrefixes", [])
    img := container.image
    prefix := exempt_image_prefixes[_]
    startswith(img, prefix)
}
