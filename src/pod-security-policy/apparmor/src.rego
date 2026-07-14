package k8spspapparmor

import future.keywords.contains
import future.keywords.if

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    container := input_containers[_]
    not is_exempt(container)
    not input_apparmor_allowed(input.review.object, container)
    msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.review.object.metadata.name, container.name, input.parameters.allowedProfiles])
}

input_apparmor_allowed(pod, container) if {
    get_apparmor_profile(pod, container) == input.parameters.allowedProfiles[_]
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

get_apparmor_profile(_, container) := out if {
    profile := object.get(container, ["securityContext", "appArmorProfile"], null)
    profile != null
    out := canonicalize_apparmor_profile(profile)
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

canonicalize_apparmor_profile(profile) := out if {
    profile.type == "RuntimeDefault"
    out := "runtime/default"
}

canonicalize_apparmor_profile(profile) := out if {
    profile.type == "Unconfined"
    out := "unconfined"
}

canonicalize_apparmor_profile(profile) := out if {
    profile.type = "Localhost"
    out := sprintf("localhost/%s", [profile.localhostProfile])
}

canonicalize_apparmor_profile(profile) := out if {
    profile == null
    out := "runtime/default"
}
