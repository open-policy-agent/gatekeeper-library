package k8snodeportnamespacerange

# Restrict NodePort ranges based on namespace name patterns
violation[{"msg": msg}] {
  input.review.object.spec.type == "NodePort"

  port := input.review.object.spec.ports[_].nodePort
  namespace := input.review.object.metadata.namespace

  some key
  rule := input.parameters.ranges[key]

  glob.match(rule.namespacePattern, [], namespace)
  not port_in_range(port, rule.portRange)

  msg := sprintf(
    "NodePort %v is not allowed for namespace %v. Allowed range: %v",
    [port, namespace, rule.portRange]
  )
}

port_in_range(port, range) {
  cleaned := trim(range, "[]")
  parts := split(cleaned, ":")
  start := to_number(parts[0])
  end := to_number(parts[1])
  port >= start
  port <= end
}
