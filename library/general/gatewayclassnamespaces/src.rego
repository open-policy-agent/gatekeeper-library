package gatewayclassnamespaces

has_key(x, k) {
  _ = x[k]
}

list_has(namespaces, namespace) {
  namespaces[_] = namespace
}

ns_allowed(params, gatewayClassName, namespace) {
  params.gatewayClasses[i].name == gatewayClassName
  list_has(params.gatewayClasses[i].namespaces, namespace)
}

violation[{"msg": msg}] {
  input.review.kind.kind == "Gateway"
  input.review.kind.group == "networking.x-k8s.io"
  ns := input.review.namespace
  gcName := input.review.object.spec.gatewayClassName
  satisfied := [good | has_key(input.parameters, "gatewayClasses") ; good = ns_allowed(input.parameters, gcName, ns)]
  not any(satisfied)  
  msg := sprintf("Can not use %v GatewayClass in %v", [gcName, ns])
}
