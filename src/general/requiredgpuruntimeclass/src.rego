package k8srequiredgpuruntimeclass

violation[{"msg": msg}] {
    pod_requests_gpu
    allowed := object.get(input, ["parameters", "allowedRuntimeClassNames"], [])
    count(allowed) > 0
    not has_allowed_runtime_class(allowed)
    msg := sprintf("Pod <%v> requests GPU resources but does not specify an allowed runtimeClassName (allowed: %v)", [input.review.object.metadata.name, allowed])
}

pod_requests_gpu {
    container := input_containers[_]
    not is_exempt(container)
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_allowed_runtime_class(allowed) {
    rc := input.review.object.spec.runtimeClassName
    rc == allowed[_]
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
