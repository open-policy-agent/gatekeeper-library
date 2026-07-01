package k8sexternalips

import future.keywords.contains
import future.keywords.if

violation contains ({"msg": msg}) if {
  input.review.kind.kind == "Service"
  input.review.kind.group == ""
  allowedIPs := {ip | ip := input.parameters.allowedIPs[_]}
  externalIPs := {ip | ip := input.review.object.spec.externalIPs[_]}
  forbiddenIPs := externalIPs - allowedIPs
  count(forbiddenIPs) > 0
  msg := sprintf("service has forbidden external IPs: %v", [forbiddenIPs])
}
