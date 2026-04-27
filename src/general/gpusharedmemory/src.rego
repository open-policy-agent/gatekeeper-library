package k8sgpusharedmemory

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    not is_exempt(container)
    has_gpu_request(container)
    not has_shm_mount(container)
    msg := sprintf("Container <%v> requests GPU resources but does not mount a memory-backed volume at /dev/shm", [container.name])
}

has_gpu_request(container) {
    gpu := container.resources.limits["nvidia.com/gpu"]
    to_number(gpu) > 0
}

has_shm_mount(container) {
    mount := container.volumeMounts[_]
    mount.mountPath == "/dev/shm"
    volume := input.review.object.spec.volumes[_]
    volume.name == mount.name
    volume.emptyDir.medium == "Memory"
}
