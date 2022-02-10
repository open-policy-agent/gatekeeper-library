package K8sBlockWildcardIngress

contains_wildcard(hostname) = true {
  hostname == ""
}

contains_wildcard(hostname) = true {
  contains(hostname, "*")
}

violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  # object.get is required to detect omitted host fields
  hostname := object.get(input.review.object.spec.rules[_], "host", "")
  contains_wildcard(hostname)
  msg := sprintf("Hostname '%v' is not allowed since it counts as a wildcard, which can be used to intercept traffic from other applications.", [hostname])
}
