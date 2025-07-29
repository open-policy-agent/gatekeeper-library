package k8spsphostfilesystem

import rego.v1

import data.lib.exclude_update.is_update

violation contains {"msg": msg, "details": {}} if {
	# spec.volumes field is immutable.
	not is_update(input.review)

	some volume in input_hostpath_volumes
	input_hostpath_violation(allowed_paths, volume)
	msg := sprintf(
		"HostPath volume %v is not allowed, pod: %v. Allowed path: %v",
		[volume, input.review.object.metadata.name, allowed_paths],
	)
}

input_hostpath_violation(allowed_paths, _) if {
	# An empty list means all host paths are blocked
	allowed_paths == []
}

input_hostpath_violation(allowed_paths, volume) if {
	not input_hostpath_allowed(allowed_paths, volume)
}

default allowed_paths := []

allowed_paths := input.parameters.allowedHostPaths

input_hostpath_allowed(allowed_paths, volume) if {
	some allowed_host_path in allowed_paths
	path_matches(allowed_host_path.pathPrefix, volume.hostPath.path)
	not allowed_host_path.readOnly == true
}

input_hostpath_allowed(allowed_paths, volume) if {
	not writeable_input_volume_mounts(volume.name)
	some allowed_host_path in allowed_paths
	path_matches(allowed_host_path.pathPrefix, volume.hostPath.path)
	allowed_host_path.readOnly
}

writeable_input_volume_mounts(volume_name) if {
	some container in input_containers
	some mount in container.volumeMounts
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
	some i, v in a
	v != b[i]
	i < n
}

input_hostpath_volumes contains volume if {
	some volume in input.review.object.spec.volumes
	"hostPath" in object.keys(volume)
}

input_containers contains container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
}
