package k8spspseccomp

import future.keywords.contains
import future.keywords.if

import data.lib.exempt_container.is_exempt

container_annotation_key_prefix := "container.seccomp.security.alpha.kubernetes.io/"

pod_annotation_key := "seccomp.security.alpha.kubernetes.io/pod"

violation contains ({"msg": msg}) if {
    not input_wildcard_allowed_profiles
    allowed_profiles := get_allowed_profiles
    container := input_containers[name]
    not is_exempt(container)
    result := get_profile(container)
    not allowed_profile(result.profile, result.file, allowed_profiles)
    msg := get_message(result.profile, result.file, name, result.location, allowed_profiles)
}

get_message(profile, _, name, location, allowed_profiles) := message if {
    message := sprintf("Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, name, location, allowed_profiles])
}

input_wildcard_allowed_profiles if {
    input.parameters.allowedProfiles[_] == "*"
}

input_wildcard_allowed_files if {
    input.parameters.allowedLocalhostFiles[_] == "*"
}

input_wildcard_allowed_files if {
    "localhost/*" == input.parameters.allowedProfiles[_]
}

# Simple allowed Profiles
allowed_profile(profile, _, allowed) if {
    not startswith(profile, "localhost/")
    profile == allowed[_]
}

# annotation localhost with wildcard
allowed_profile(profile, _, allowed) if {
    "localhost/*" == allowed[_]
    startswith(profile, "localhost/")
}

# annotation localhost without wildcard
allowed_profile(profile, _, allowed) if {
    startswith(profile, "localhost/")
    profile == allowed[_]
}

# The profiles explicitly in the list
get_allowed_profiles contains allowed if {
    allowed := input.parameters.allowedProfiles[_]
}

# Seccomp Localhost to annotation translation
get_allowed_profiles contains allowed if {
    profile := input.parameters.allowedProfiles[_]
    not contains(profile, "/")
    file := object.get(input.parameters, "allowedLocalhostFiles", [])[_]
    allowed := canonicalize_seccomp_profile({"type": profile, "localhostProfile": file}, "")[_]
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
get_profile(container) := {"profile": profile, "file": file, "location": location} if {
    not has_securitycontext_container(container)
    profile := canonicalize_seccomp_profile(input.review.object.spec.securityContext.seccompProfile, canonicalize_runtime_default_profile)[_]
    file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
    location := "pod securityContext"
}

# Container profile as defined in containers securityContext
get_profile(container) := {"profile": profile, "file": file, "location": location} if {
    has_securitycontext_container(container)
    profile := canonicalize_seccomp_profile(container.securityContext.seccompProfile, canonicalize_runtime_default_profile)[_]
    file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
    location := "container securityContext"
}

# Container profile missing
get_profile(container) := {"profile": "not configured", "file": "", "location": "no explicit profile found"} if {
    not has_securitycontext_container(container)
    not has_securitycontext_pod
    not has_annotation(get_container_annotation_key(container.name))
    not has_annotation(pod_annotation_key)
}

has_annotation(annotation) if {
    input.review.object.metadata.annotations[annotation]
}

has_securitycontext_pod if {
    input.review.object.spec.securityContext.seccompProfile
}

has_securitycontext_container(container) if {
    container.securityContext.seccompProfile
}

get_container_annotation_key(name) := annotation if {
    annotation := concat("", [container_annotation_key_prefix, name])
}

input_containers[container.name] := container if {
    container := input.review.object.spec.containers[_]
}

input_containers[container.name] := container if {
    container := input.review.object.spec.initContainers[_]
}

input_containers[container.name] := container if {
    container := input.review.object.spec.ephemeralContainers[_]
}

canonicalize_runtime_default_profile := out if {
    "runtime/default" == input.parameters.allowedProfiles[_]
    out := "runtime/default"
} else := out if {
    "docker/default" == input.parameters.allowedProfiles[_]
    out := "docker/default"
} else := out if {
    out := "runtime/default"
}

canonicalize_seccomp_profile(profile, def) := out if {
    profile.type == "RuntimeDefault"
    def == "" 
    out := ["runtime/default", "docker/default"]
} else := out if {
    profile.type == "RuntimeDefault"
    def != ""
    out := [def]
} else := out if {
    profile.type == "Localhost"
    out := [sprintf("localhost/%s", [profile.localhostProfile])]
} else := out if {
    profile.type == "Unconfined"
    out := ["unconfined"]
} 
