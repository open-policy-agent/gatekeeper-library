package verifydeprecatedapi

import rego.v1

violation contains {"msg": msg} if {
	some kvs in input.parameters.kvs
	kvs.deprecatedAPI == input.review.object.apiVersion
	some kind in kvs.kinds
	kind == input.review.object.kind

	msg := message(kind, input.review.object.apiVersion, input.parameters.k8sVersion, kvs.targetAPI)
}

message(kind, api_version, k8s_version, target_api) := msg if {
	not match(target_api)
	msg := sprintf(
		"API %v for %v is deprecated in Kubernetes version %v, please use %v instead",
		[kind, api_version, k8s_version, target_api],
	)
}

message(kind, api_version, k8s_version, target_api) := msg if {
	match(target_api)
	msg := sprintf(
		"API %v for %v is deprecated in Kubernetes version %v, please see Kubernetes API deprecation guide",
		[kind, api_version, k8s_version],
	)
}

match("None")
