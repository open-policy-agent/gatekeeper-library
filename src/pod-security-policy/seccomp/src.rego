package k8spspseccomp

import data.lib.exempt_container.is_exempt

container_annotation_key_prefix = "container.seccomp.security.alpha.kubernetes.io/"

pod_annotation_key = "seccomp.security.alpha.kubernetes.io/pod"

violation[{"msg": msg}] {
	not input_wildcard_allowed
	container := input_containers[name]
	not is_exempt(container)
	result := get_profile(container)
	not allowed_profile(result.profile)
	msg := sprintf("Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [result.profile, name, result.location, input.parameters.allowedProfiles])
}

input_wildcard_allowed {
	input.parameters.allowedProfiles[_] == "*"
}

allowed_profile(profile) {
	profile == input.parameters.allowedProfiles[_]
}

# Container profile as defined in pod annotation
get_profile(container) = {"profile": profile, "location": location} {
	not has_securitycontext_container(container)
	not has_annotation(get_container_annotation_key(container.name))
	profile := input.review.object.metadata.annotations[pod_annotation_key]
	location := sprintf("annotation %v", [pod_annotation_key])
}

# Container profile as defined in container annotation
get_profile(container) = {"profile": profile, "location": location} {
	container_annotation := get_container_annotation_key(container.name)
	has_annotation(container_annotation)
	profile := input.review.object.metadata.annotations[container_annotation]
	location := sprintf("annotation %v", [container_annotation])
}

# Container profile as defined in pods securityContext
get_profile(container) = {"profile": profile, "location": location} {
	not has_securitycontext_container(container)
	not has_annotation(get_container_annotation_key(container.name))
	not has_annotation(pod_annotation_key)
	profile := input.review.object.spec.securityContext.seccompProfile.type
	location := "pod securityContext"
}

# Container profile as defined in containers securityContext
get_profile(container) = {"profile": profile, "location": location} {
    not has_annotation(get_container_annotation_key(container.name))
	has_securitycontext_container(container)
	profile := container.securityContext.seccompProfile.type
	location := "container securityContext"
}

# Container profile missing
get_profile(container) = {"profile": "not configured", "location": "no explicit profile found"} {
	not has_annotation(get_container_annotation_key(container.name))
	not has_annotation(pod_annotation_key)
	not has_securitycontext_pod
	not has_securitycontext_container(container)
}

has_annotation(annotation) {
	input.review.object.metadata.annotations[annotation]
}

has_securitycontext_pod {
	input.review.object.spec.securityContext.seccompProfile
}

has_securitycontext_container(container) {
	container.securityContext.seccompProfile
}

get_container_annotation_key(name) = annotation {
	annotation := concat("", [container_annotation_key_prefix, name])
}

input_containers[container.name] = container {
	container := input.review.object.spec.containers[_]
}

input_containers[container.name] = container {
	container := input.review.object.spec.initContainers[_]
}
