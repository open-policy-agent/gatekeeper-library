package k8sallowedrepos

import rego.v1

violation contains {"msg": msg} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not strings.any_prefix_match(container.image, input.parameters.repos)

	msg := sprintf(
		"%s <%v> has an invalid image repo <%v>, allowed repos are %v",
		[trim_suffix(type, "s"), container.name, container.image, input.parameters.repos],
	)
}
