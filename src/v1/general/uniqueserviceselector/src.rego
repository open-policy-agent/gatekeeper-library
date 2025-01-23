package k8suniqueserviceselector

import rego.v1

make_apiversion(kind) := sprintf("%v/%v", [kind.group, kind.version]) if kind.group != ""

make_apiversion(kind) := kind.version if kind.group == ""

identical(obj, review) if {
	obj.metadata.namespace == review.namespace
	obj.metadata.name == review.name
	obj.kind == review.kind.kind
	obj.apiVersion == make_apiversion(review.kind)
}

flatten_selector(obj) := concat(",", sort([s |
	some key, val in obj.spec.selector
	s := concat(":", [key, val])
]))

violation contains {"msg": msg} if {
	input.review.kind.kind == "Service"
	input.review.kind.version == "v1"
	input.review.kind.group == ""
	input_selector := flatten_selector(input.review.object)
	some namespace, name
	other := data.inventory.namespace[namespace][_].Service[name]
	not identical(other, input.review)
	other_selector := flatten_selector(other)
	input_selector == other_selector
	msg := sprintf("same selector as service <%v> in namespace <%v>", [name, namespace])
}
