package k8spspseccomp

import rego.v1

import data.lib.exempt_container.is_exempt

container_annotation_key_prefix := "container.seccomp.security.alpha.kubernetes.io/"

pod_annotation_key := "seccomp.security.alpha.kubernetes.io/pod"

violation contains {"msg": msg} if {
	not input_wildcard_allowed_profiles
	some name, container in input_containers
	not is_exempt(container)
	result := get_profile(container)
	not allowed_profile(result.profile, allowed_profiles)
	msg := sprintf(
		"Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v",
		[result.profile, name, result.location, allowed_profiles],
	)
}

input_wildcard_allowed_profiles if "*" in input.parameters.allowedProfiles

input_wildcard_allowed_files if "*" in input.parameters.allowedLocalhostFiles

input_wildcard_allowed_files if "localhost/*" in input.parameters.allowedProfiles

# Simple allowed Profiles
allowed_profile(profile, allowed) if {
	not startswith(profile, "localhost/")
	profile in allowed
}

# annotation localhost with wildcard
allowed_profile(profile, allowed) if {
	"localhost/*" in allowed
	startswith(profile, "localhost/")
}

# annotation localhost without wildcard
allowed_profile(profile, allowed) if {
	startswith(profile, "localhost/")
	profile in allowed
}

# The profiles explicitly in the list
allowed_profiles contains allowed if {
	some allowed in input.parameters.allowedProfiles
}

# Seccomp Localhost to annotation translation
allowed_profiles contains allowed if {
	some profile in input.parameters.allowedProfiles
	not contains(profile, "/")
	some file in input.parameters.allowedLocalhostFiles
	some allowed in canonicalize_seccomp_profile({"type": profile, "localhostProfile": file}, "")
}

# Container profile as defined in pod annotation
get_profile(container) := {"profile": profile, "file": "", "location": location} if {
	not has_securitycontext_container(container)
	not has_annotation(get_container_annotation_key(container.name))
	not has_securitycontext_pod
	profile := input.review.object.metadata.annotations[pod_annotation_key]
	location := sprintf("annotation %v", [pod_annotation_key])
}

# Container profile as defined in container annotation
get_profile(container) := {"profile": profile, "file": "", "location": location} if {
	not has_securitycontext_container(container)
	not has_securitycontext_pod
	container_annotation := get_container_annotation_key(container.name)
	has_annotation(container_annotation)
	profile := input.review.object.metadata.annotations[container_annotation]
	location := sprintf("annotation %v", [container_annotation])
}

# Container profile as defined in pods securityContext
get_profile(container) := {"profile": profile, "file": file, "location": "pod securityContext"} if {
	not has_securitycontext_container(container)
	some profile in canonicalize_seccomp_profile(
		input.review.object.spec.securityContext.seccompProfile,
		canonicalize_runtime_default_profile,
	)
	file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
}

# Container profile as defined in containers securityContext
get_profile(container) := {"profile": profile, "file": file, "location": "container securityContext"} if {
	has_securitycontext_container(container)
	some profile in canonicalize_seccomp_profile(
		container.securityContext.seccompProfile,
		canonicalize_runtime_default_profile,
	)
	file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
}

# Container profile missing
get_profile(container) := {"profile": "not configured", "file": "", "location": "no explicit profile found"} if {
	not has_securitycontext_container(container)
	not has_securitycontext_pod
	not has_annotation(get_container_annotation_key(container.name))
	not has_annotation(pod_annotation_key)
}

has_annotation(annotation) if input.review.object.metadata.annotations[annotation]

has_securitycontext_pod if input.review.object.spec.securityContext.seccompProfile

has_securitycontext_container(container) if container.securityContext.seccompProfile

get_container_annotation_key(name) := concat("", [container_annotation_key_prefix, name])

input_containers[container.name] := container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
}

default canonicalize_runtime_default_profile := "runtime/default"

canonicalize_runtime_default_profile := "docker/default" if {
	"docker/default" in input.parameters.allowedProfiles
}

canonicalize_seccomp_profile(profile, def) := ["runtime/default", "docker/default"] if {
	profile.type == "RuntimeDefault"
	def == ""
} else := [def] if {
	profile.type == "RuntimeDefault"
	def != ""
} else := [sprintf("localhost/%s", [profile.localhostProfile])] if {
	profile.type == "Localhost"
} else := ["unconfined"] if {
	profile.type == "Unconfined"
}
