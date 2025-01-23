# regal ignore:prefer-snake-case
package K8sBlockWildcardIngress

import rego.v1

contains_wildcard("")

contains_wildcard(hostname) if contains(hostname, "*")

violation contains {"msg": msg} if {
	input.review.kind.kind == "Ingress"

	some rule in input.review.object.spec.rules

	# object.get is required to detect omitted host fields
	hostname := object.get(rule, "host", "")
	contains_wildcard(hostname)
	msg := sprintf(
		# regal ignore:line-length
		"Hostname '%v' is not allowed since it counts as a wildcard, which can be used to intercept traffic from other applications.",
		[hostname],
	)
}
