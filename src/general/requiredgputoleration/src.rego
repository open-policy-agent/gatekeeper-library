package k8srequiredgputoleration

violation[{"msg": msg}] {
    pod_requests_gpu
    toleration_key := object.get(input, ["parameters", "tolerationKey"], "")
    toleration_key != ""
    not has_toleration(toleration_key)
    msg := sprintf("Pod <%v> requests GPU resources but does not tolerate taint key <%v>", [input.review.object.metadata.name, toleration_key])
}

pod_requests_gpu {
    container := input_containers[_]
    not is_exempt(container)
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_toleration(key) {
    toleration := input.review.object.spec.tolerations[_]
    toleration.key == key
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
