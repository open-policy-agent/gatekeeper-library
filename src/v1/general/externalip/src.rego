package k8sexternalips

import rego.v1

violation contains {"msg": msg} if {
	input.review.kind.kind == "Service"
	input.review.kind.group == ""
	allowed_ips := {ip | some ip in input.parameters.allowedIPs}
	external_ips := {ip | some ip in input.review.object.spec.externalIPs}
	forbidden_ips := external_ips - allowed_ips
	count(forbidden_ips) > 0
	msg := sprintf("service has forbidden external IPs: %v", [forbidden_ips])
}
