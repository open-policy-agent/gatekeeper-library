package k8spspseccomp

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	not input_wildcard_allowed_profiles
	some name, container in input_containers
	not is_exempt(container)
	result := get_profile(container)
	not allowed_profile(result.profile, result.file, allowed_profiles)
	msg := get_message(result.profile, result.file, name, result.location, allowed_profiles)
}

get_message(profile, _, name, location, allowed_profiles) := message if {
	profile != "Localhost"
	message := sprintf(
		"Seccomp profile '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v",
		[profile, name, location, allowed_profiles],
	)
}

get_message("Localhost", file, name, location, allowed_profiles) := sprintf(
	"Seccomp profile 'Localhost' with file '%v' is not allowed for container '%v'. Found at: %v. Allowed profiles: %v",
	[file, name, location, allowed_profiles],
)

input_wildcard_allowed_profiles if "*" in input.parameters.allowedProfiles

input_wildcard_allowed_files if "*" in input.parameters.allowedLocalhostFiles

allowed_profile(_, _, _) if {
	input_wildcard_allowed_profiles
}

allowed_profile("Localhost", _, _) if {
	input_wildcard_allowed_files
}

# Simple allowed Profiles
allowed_profile(profile, _, allowed) if {
	profile != "Localhost"
	some allow_profile in allowed
	profile == allow_profile.type
}

# annotation localhost without wildcard
allowed_profile("Localhost", file, allowed) if {
	some allow_profile in allowed
	allow_profile.type == "Localhost"
	file == allow_profile.localHostProfile
}

# The profiles explicitly in the list
allowed_profiles contains {"type": profile} if {
	some profile in input.parameters.allowedProfiles
	profile != "Localhost"
}

allowed_profiles contains {"type": "Localhost", "localHostProfile": file} if {
	some profile in input.parameters.allowedProfiles
	profile == "Localhost"
	some file in object.get(input.parameters, "allowedLocalhostFiles", [""])
}

# Container profile as defined in containers securityContext
get_profile(container) := {
	"profile": container.securityContext.seccompProfile.type,
	"file": object.get(container.securityContext.seccompProfile, "localhostProfile", ""),
	"location": "container securityContext",
} if {
	container.securityContext.seccompProfile
}

# Container profile as defined in pods securityContext
get_profile(container) := {
	"profile": input.review.object.spec.securityContext.seccompProfile.type,
	"file": object.get(input.review.object.spec.securityContext.seccompProfile, "localhostProfile", ""),
	"location": "pod securityContext",
} if {
	not container.securityContext.seccompProfile
}

# Container profile missing
get_profile(container) := {
	"profile": "not configured",
	"file": "",
	"location": "no explicit profile found",
} if {
	not container.securityContext.seccompProfile
	not input.review.object.spec.securityContext.seccompProfile
}

input_containers[container.name] := container if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
}
