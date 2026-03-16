package k8sgpuresourcelimits

violation[{"msg": msg}] {
    container := input_containers[_]
    not is_exempt(container)
    gpu_count := to_number(container.resources.limits["nvidia.com/gpu"])
    gpu_count > 0
    max_gpu := object.get(input, ["parameters", "maxGpuPerContainer"], 0)
    max_gpu > 0
    gpu_count > max_gpu
    msg := sprintf("Container <%v> requests %v GPUs, which exceeds the maximum allowed %v", [container.name, gpu_count, max_gpu])
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
