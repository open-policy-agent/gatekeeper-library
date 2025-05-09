package k8shttpsonly

import rego.v1

violation contains {"msg": msg} if {
	not https_complete(ingress)
	not tls_is_optional
	msg := sprintf(
		"Ingress should be https. tls configuration and allow-http=false annotation are required for %v",
		[ingress.metadata.name],
	)
}

violation contains {"msg": msg} if {
	not annotation_complete(ingress)
	tls_is_optional
	msg := sprintf("Ingress should be https. The allow-http=false annotation is required for %v", [ingress.metadata.name])
}

ingress := input.review.object if {
	input.review.object.kind == "Ingress"
	regex.match(`^(extensions|networking.k8s.io)/`, input.review.object.apiVersion)
}

https_complete(ingress) if {
	ingress.spec.tls
	count(ingress.spec.tls) > 0
	ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
}

annotation_complete(ingress) if {
	ingress.metadata.annotations["kubernetes.io/ingress.allow-http"] == "false"
}

tls_is_optional if input.parameters.tlsOptional == true
