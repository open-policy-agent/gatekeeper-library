package k8spsphostfilesystem

violation[{"msg": msg, "details": {}}] {
    volume := input_hostpath_volumes[_]
    allowedPaths := get_allowed_paths(input)
    input_hostpath_violation(allowedPaths, volume)
    msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.review.object.metadata.name, allowedPaths])
}

input_hostpath_violation(allowedPaths, volume) {
    # An empty list means all host paths are blocked
    allowedPaths == []
}
input_hostpath_violation(allowedPaths, volume) {
    not input_hostpath_allowed(allowedPaths, volume)
}

get_allowed_paths(arg) = out {
    not arg.parameters
    out = []
}
get_allowed_paths(arg) = out {
    not arg.parameters.allowedHostPaths
    out = []
}
get_allowed_paths(arg) = out {
    out = arg.parameters.allowedHostPaths
}

input_hostpath_allowed(allowedPaths, volume) {
    allowedHostPath := allowedPaths[_]
    path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
    not allowedHostPath.readOnly == true
}

input_hostpath_allowed(allowedPaths, volume) {
    allowedHostPath := allowedPaths[_]
    path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
    allowedHostPath.readOnly
    not writeable_input_volume_mounts(volume.name)
}

writeable_input_volume_mounts(volume_name) {
    container := input_containers[_]
    mount := container.volumeMounts[_]
    mount.name == volume_name
    not mount.readOnly
}

# This allows "/foo", "/foo/", "/foo/bar" etc., but
# disallows "/fool", "/etc/foo" etc.
path_matches(prefix, path) {
    a := split(trim(prefix, "/"), "/")
    b := split(trim(path, "/"), "/")
    prefix_matches(a, b)
}
prefix_matches(a, b) {
    count(a) <= count(b)
    not any_not_equal_upto(a, b, count(a))
}

any_not_equal_upto(a, b, n) {
    a[i] != b[i]
    i < n
}

input_hostpath_volumes[v] {
    v := input.review.object.spec.volumes[_]
    has_field(v, "hostPath")
}

# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}
input_containers[c] {
    c := input.review.object.spec.containers[_]
}

input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
