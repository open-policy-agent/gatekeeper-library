package k8spspapparmor

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)
	not input_apparmor_allowed(input.review.object, container)

	msg := sprintf(
		"AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v",
		[input.review.object.metadata.name, container.name, input.parameters.allowedProfiles],
	)
}

input_apparmor_allowed(pod, container) if get_apparmor_profile(pod, container) in input.parameters.allowedProfiles

get_apparmor_profile(_, container) := canonicalize_apparmor_profile(profile) if {
	profile := object.get(container, ["securityContext", "appArmorProfile"], null)
	profile != null
}

get_apparmor_profile(pod, container) := out if {
	profile := object.get(container, ["securityContext", "appArmorProfile"], null)
	profile == null
	out := pod.metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
}

get_apparmor_profile(pod, container) := out if {
	profile := object.get(container, ["securityContext", "appArmorProfile"], null)
	profile == null
	not pod.metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
	out := canonicalize_apparmor_profile(object.get(pod, ["spec", "securityContext", "appArmorProfile"], null))
}

canonicalize_apparmor_profile(profile) := "runtime/default" if profile.type == "RuntimeDefault"

canonicalize_apparmor_profile(profile) := "unconfined" if profile.type == "Unconfined"

canonicalize_apparmor_profile(profile) := sprintf("localhost/%s", [profile.localhostProfile]) if {
	profile.type = "Localhost"
}

canonicalize_apparmor_profile(null) := "runtime/default"
