package k8shttpsonly

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  regex.match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)
  ingress := input.review.object
  not https_complete(ingress)
  not tls_is_optional
  msg := sprintf("Ingress should be https. tls configuration and allow-http=false annotation are required for %v", [ingress.metadata.name])
}

violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  regex.match("^(extensions|networking.k8s.io)/", input.review.object.apiVersion)
  ingress := input.review.object
  not annotation_complete(ingress)
  tls_is_optional
  msg := sprintf("Ingress should be https. The allow-http=false annotation is required for %v", [ingress.metadata.name])
}

https_complete(ingress) = true {
  ingress.spec["tls"]
  count(ingress.spec.tls) > 0
  ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
}

annotation_complete(ingress) = true {
  ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
}

tls_is_optional {
  parameters := object.get(input, "parameters", {})
  object.get(parameters, "tlsOptional", false) == true
}
