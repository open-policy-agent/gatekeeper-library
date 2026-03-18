package k8snounsupportedgpu

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    has_gpu_request(container)
    not has_nvidia_env(container)
    msg := sprintf("Container <%v> requests nvidia.com/gpu but does not set the NVIDIA_VISIBLE_DEVICES environment variable", [container.name])
}

has_gpu_request(container) {
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_nvidia_env(container) {
    env := container.env[_]
    env.name == "NVIDIA_VISIBLE_DEVICES"
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

is_exempt(container) {
    exempt_images := object.get(input, ["parameters", "exemptImages"], [])
    img := container.image
    exemption := exempt_images[_]
    _matches_exemption(img, exemption)
}

_matches_exemption(img, exemption) {
    not endswith(exemption, "*")
    exemption == img
}

_matches_exemption(img, exemption) {
    endswith(exemption, "*")
    prefix := trim_suffix(exemption, "*")
    startswith(img, prefix)
}
