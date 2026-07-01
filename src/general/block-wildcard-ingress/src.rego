package K8sBlockWildcardIngress

import future.keywords.contains
import future.keywords.if

contains_wildcard(hostname) if {
  hostname == ""
}

contains_wildcard(hostname) if {
  contains(hostname, "*")
}

violation contains ({"msg": msg}) if {
  input.review.kind.kind == "Ingress"

  # object.get is required to detect omitted host fields
  hostname := object.get(input.review.object.spec.rules[_], "host", "")
  contains_wildcard(hostname)
  msg := sprintf("Hostname '%v' is not allowed since it counts as a wildcard, which can be used to intercept traffic from other applications.", [hostname])
}
