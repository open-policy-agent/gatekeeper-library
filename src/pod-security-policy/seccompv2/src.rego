package k8spspseccomp

import future.keywords.contains
import future.keywords.if

import data.lib.exempt_container.is_exempt

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
    profile != "Localhost"
    message := sprintf("Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, name, location, allowed_profiles])
}

get_message(profile, file, name, location, allowed_profiles) := message if {
    profile == "Localhost"
    message := sprintf("Seccomp profile '%v' with file '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v", [profile, file, name, location, allowed_profiles])
}

input_wildcard_allowed_profiles if {
    input.parameters.allowedProfiles[_] == "*"
}

input_wildcard_allowed_files if {
    input.parameters.allowedLocalhostFiles[_] == "*"
}

allowed_profile(_, _, _) if {
    input_wildcard_allowed_profiles
}

allowed_profile(profile, _, _) if {
    profile == "Localhost"
    input_wildcard_allowed_files
}

# Simple allowed Profiles
allowed_profile(profile, _, allowed) if {
    profile != "Localhost"
    allow_profile = allowed[_]
    profile == allow_profile.type
}

# annotation localhost without wildcard
allowed_profile(profile, file, allowed) if {
    profile == "Localhost"
    allow_profile = allowed[_]
    allow_profile.type == "Localhost"
    file == allow_profile.localHostProfile
}

# The profiles explicitly in the list
get_allowed_profiles contains allowed if {
    profile := input.parameters.allowedProfiles[_]
    profile != "Localhost"
    allowed := {"type": profile}
}

get_allowed_profiles contains allowed if {
    profile := input.parameters.allowedProfiles[_]
    profile == "Localhost"
    file := object.get(input.parameters, "allowedLocalhostFiles", [""])[_]
    allowed := {"type": "Localhost", "localHostProfile": file}
}

# Container profile as defined in containers securityContext
get_profile(container) := {"profile": profile, "file": file, "location": location} if {
    has_securitycontext_container(container)
    profile := container.securityContext.seccompProfile.type
    file := object.get(container.securityContext.seccompProfile, "localhostProfile", "")
    location := "container securityContext"
}

# Container profile as defined in pods securityContext
get_profile(container) := {"profile": profile, "file": file, "location": location} if {
    not has_securitycontext_container(container)
    profile := input.review.object.spec.securityContext.seccompProfile.type
    file := object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", "")
    location := "pod securityContext"
}

# Container profile missing
get_profile(container) := {"profile": "not configured", "file": "", "location": "no explicit profile found"} if {
    not has_securitycontext_container(container)
    not has_securitycontext_pod
}

has_securitycontext_pod if {
    input.review.object.spec.securityContext.seccompProfile
}

has_securitycontext_container(container) if {
    container.securityContext.seccompProfile
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
