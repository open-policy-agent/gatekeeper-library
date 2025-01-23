package k8sdisallowedrepos

import rego.v1

violation contains {"msg": msg} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	strings.any_prefix_match(container.image, input.parameters.repos)

	msg := sprintf(
		"%s <%v> has an invalid image repo <%v>, disallowed repos are %v",
		[trim_suffix(type, "s"), container.name, container.image, input.parameters.repos],
	)
}
