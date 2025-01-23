package k8srequiredresources

import rego.v1

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg} if {
	general_violation[{"msg": msg, "field": "containers"}]
}

violation contains {"msg": msg} if {
	general_violation[{"msg": msg, "field": "initContainers"}]
}

general_violation contains {"msg": msg, "field": field} if {
	some [field, container] in non_exempt_containers
	provided := {key | some key in object.keys(container.resources.limits)}
	required := {resource_type | some resource_type in input.parameters.limits}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("container <%v> does not have <%v> limits defined", [container.name, missing])
}

general_violation contains {"msg": msg, "field": field} if {
	some [field, container] in non_exempt_containers
	provided := {key | some key in object.keys(container.resources.requests)}
	required := {resource_type | some resource_type in input.parameters.requests}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("container <%v> does not have <%v> requests defined", [container.name, missing])
}

non_exempt_containers contains [field, container] if {
	some field, containers in input.review.object.spec
	some container in containers
	not is_exempt(container)
}
