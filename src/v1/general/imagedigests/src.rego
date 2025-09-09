package k8simagedigests

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)
	not regex.match(`@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`, container.image)
	msg := sprintf(
		"%s <%v> uses an image without a digest <%v>",
		[trim_suffix(type, "s"), container.name, container.image],
	)
}
