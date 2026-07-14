package k8spsphostfilesystem

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
    # spec.volumes field is immutable.
    not is_update(input.review)

    volume := input_hostpath_volumes[_]
    allowedPaths := get_allowed_paths(input)
    input_hostpath_violation(allowedPaths, volume)
    msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.review.object.metadata.name, allowedPaths])
}

input_hostpath_violation(allowedPaths, _) if {
    # An empty list means all host paths are blocked
    allowedPaths == []
}

input_hostpath_violation(allowedPaths, volume) if {
    not input_hostpath_allowed(allowedPaths, volume)
}

get_allowed_paths(arg) := out if {
    not arg.parameters
    out = []
}

get_allowed_paths(arg) := out if {
    not arg.parameters.allowedHostPaths
    out = []
}

get_allowed_paths(arg) := out if {
    out = arg.parameters.allowedHostPaths
}

input_hostpath_allowed(allowedPaths, volume) if {
    allowedHostPath := allowedPaths[_]
    path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
    not allowedHostPath.readOnly == true
}

input_hostpath_allowed(allowedPaths, volume) if {
    allowedHostPath := allowedPaths[_]
    path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
    allowedHostPath.readOnly
    not writeable_input_volume_mounts(volume.name)
}

writeable_input_volume_mounts(volume_name) if {
    container := input_containers[_]
    mount := container.volumeMounts[_]
    mount.name == volume_name
    not mount.readOnly
}

# This allows "/foo", "/foo/", "/foo/bar" etc., but
# disallows "/fool", "/etc/foo" etc.
path_matches(prefix, path) if {
    a := path_array(prefix)
    b := path_array(path)
    prefix_matches(a, b)
}

path_array(p) := out if {
    p != "/"
    out := split(trim(p, "/"), "/")
}

# This handles the special case for "/", since
# split(trim("/", "/"), "/") == [""]
path_array("/") := []

prefix_matches(a, b) if {
    count(a) <= count(b)
    not any_not_equal_upto(a, b, count(a))
}

any_not_equal_upto(a, b, n) if {
    a[i] != b[i]
    i < n
}

input_hostpath_volumes contains v if {
    v := input.review.object.spec.volumes[_]
    has_field(v, "hostPath")
}

# has_field returns whether an object has a field
has_field(object, field) if {
    object[field]
}

input_containers contains c if {
    c := input.review.object.spec.containers[_]
}

input_containers contains c if {
    c := input.review.object.spec.initContainers[_]
}

input_containers contains c if {
    c := input.review.object.spec.ephemeralContainers[_]
}
