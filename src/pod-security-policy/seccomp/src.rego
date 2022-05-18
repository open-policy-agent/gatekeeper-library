package k8spspseccomp

import data.lib.exempt_container.is_exempt

container_annotation_key_prefix = "container.seccomp.security.alpha.kubernetes.io/"

pod_annotation_key = "seccomp.security.alpha.kubernetes.io/pod"

naming_translation = {
    # securityContext -> annotation
    "RuntimeDefault": ["runtime/default", "docker/default"],
    "Unconfined": ["unconfined"],
    "Localhost": ["localhost"],
    # annotation -> securityContext
    "runtime/default": ["RuntimeDefault"],
    "docker/default": ["RuntimeDefault"],
    "unconfined": ["Unconfined"],
    "localhost": ["Localhost"],
}

violation[{"msg": msg}] {
    not input_wildcard_allowed_profiles
    allowed_profiles := get_allowed_profiles
    container := input_containers[name]
    not is_exempt(container)
    result := get_profile(container)
    not allowed_profile(result.profile, result.file, allowed_profiles)
    msg := get_message(result.profile, result.file, name, result.location, allowed_profiles)
}

get_message(profile, file, name, location, allowed_profiles) = message {
    not profile == "Localhost"
    message := sprintf("Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, name, location, allowed_profiles])
}

get_message(profile, file, name, location, allowed_profiles) = message {
    profile == "Localhost"
    message := sprintf("Seccomp profile '%v' with file '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, file, name, location, allowed_profiles])
}

input_wildcard_allowed_profiles {
    input.parameters.allowedProfiles[_] == "*"
}

input_wildcard_allowed_files {
    input.parameters.allowedLocalhostFiles[_] == "*"
}

input_wildcard_allowed_files {
    "localhost/*" == input.parameters.allowedProfiles[_]
}

# Simple allowed Profiles
allowed_profile(profile, file, allowed) {
    not startswith(lower(profile), "localhost")
    profile == allowed[_]
}

# seccomp Localhost without wildcard
allowed_profile(profile, file, allowed) {
    profile == "Localhost"
    not input_wildcard_allowed_files
    profile == allowed[_]
    allowed_files := {x | x := object.get(input.parameters, "allowedLocalhostFiles", [])[_]} | get_annotation_localhost_files
    file == allowed_files[_]
}

# seccomp Localhost with wildcard
allowed_profile(profile, file, allowed) {
    profile == "Localhost"
    input_wildcard_allowed_files
    profile == allowed[_]
}

# annotation localhost with wildcard
allowed_profile(profile, file, allowed) {
    "localhost/*" == allowed[_]
    startswith(profile, "localhost/")
}

# annotation localhost without wildcard
allowed_profile(profile, file, allowed) {
    startswith(profile, "localhost/")
    profile == allowed[_]
}

# Localhost files from annotation scheme
get_annotation_localhost_files[file] {
    profile := input.parameters.allowedProfiles[_]
    startswith(profile, "localhost/")
    file := replace(profile, "localhost/", "")
}

# The profiles explicitly in the list
get_allowed_profiles[allowed] {
    allowed := input.parameters.allowedProfiles[_]
}

# The simply translated profiles
get_allowed_profiles[allowed] {
    profile := input.parameters.allowedProfiles[_]
    not startswith(lower(profile), "localhost")
    allowed := naming_translation[profile][_]
}

# Seccomp Localhost to annotation translation
get_allowed_profiles[allowed] {
    profile := input.parameters.allowedProfiles[_]
    profile == "Localhost"
    file := object.get(input.parameters, "allowedLocalhostFiles", [])[_]
    allowed := sprintf("%v/%v", [naming_translation[profile][_], file])
}

# Annotation localhost to Seccomp translation
get_allowed_profiles[allowed] {
    profile := input.parameters.allowedProfiles[_]
    startswith(profile, "localhost")
    allowed := naming_translation.localhost[_]
}

# Container profile as defined in pod annotation
get_profile(container) = {"profile": profile, "file": "", "location": location} {
    not has_securitycontext_container(container)
    not has_annotation(get_container_annotation_key(container.name))
    not has_securitycontext_pod
    profile := input.review.object.metadata.annotations[pod_annotation_key]
    location := sprintf("annotation %v", [pod_annotation_key])
}

# Container profile as defined in container annotation
get_profile(container) = {"profile": profile, "file": "", "location": location} {
    not has_securitycontext_container(container)
    not has_securitycontext_pod
    container_annotation := get_container_annotation_key(container.name)
    has_annotation(container_annotation)
    profile := input.review.object.metadata.annotations[container_annotation]
    location := sprintf("annotation %v", [container_annotation])
}

# Container profile as defined in pods securityContext
get_profile(container) = {"profile": profile, "file": file, "location": location} {
    not has_securitycontext_container(container)
    profile := input.review.object.spec.securityContext.seccompProfile.type
    file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
    location := "pod securityContext"
}

# Container profile as defined in containers securityContext
get_profile(container) = {"profile": profile, "file": file, "location": location} {
    has_securitycontext_container(container)
    profile := container.securityContext.seccompProfile.type
    file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
    location := "container securityContext"
}

# Container profile missing
get_profile(container) = {"profile": "not configured", "file": "", "location": "no explicit profile found"} {
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

input_containers[container.name] = container {
    container := input.review.object.spec.ephemeralContainers[_]
}
