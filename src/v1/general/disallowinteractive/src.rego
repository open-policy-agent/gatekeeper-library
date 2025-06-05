package k8sdisallowinteractivetty

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
	some type in ["containers", "initContainers", "ephemeralContainers"]
	some container in input.review.object.spec[type]
	not is_exempt(container)
	input_allow_interactive_fields(container)

	msg := sprintf(
		"Containers using tty or stdin (%v) are not allowed running image: %v",
		[container.name, container.image],
	)
}

input_allow_interactive_fields(c) if {
	"stdin" in object.keys(c)
	not c.stdin == false
}

input_allow_interactive_fields(c) if {
	"tty" in object.keys(c)
	not c.tty == false
}
