package k8suniqueingresshost

import rego.v1

identical(obj, review) if {
	obj.metadata.namespace == review.object.metadata.namespace
	obj.metadata.name == review.object.metadata.name
}

violation contains {"msg": msg} if {
	input.review.kind.kind == "Ingress"
	regex.match(`^(extensions|networking.k8s.io)$`, input.review.kind.group)
	host := input.review.object.spec.rules[_].host

	some otherapiversion
	other := data.inventory.namespace[_][otherapiversion].Ingress[_]

	# false positive
	# regal ignore:non-loop-expression
	regex.match(`^(extensions|networking.k8s.io)/.+$`, otherapiversion)
	other.spec.rules[_].host == host
	not identical(other, input.review)
	msg := sprintf("ingress host conflicts with an existing ingress <%v>", [host])
}
