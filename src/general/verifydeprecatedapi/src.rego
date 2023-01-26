package verifydeprecatedapi

violation[{"msg": msg}] {
  kvs := input.parameters.kvs[_]
  kvs.deprecatedAPI == input.review.object.apiVersion
  k := kvs.kinds[_]
  k == input.review.object.kind
  msg := get_message(input.review.object.kind, input.review.object.apiVersion, input.parameters.k8sVersion, kvs.targetAPI)
}

get_message(kind, apiVersion, k8sVersion, targetAPI) = msg {
  not match(targetAPI)
  msg := sprintf("API %v for %v is deprecated in Kubernetes version %v, please use %v instead", [kind, apiVersion, k8sVersion, targetAPI])
}

get_message(kind, apiVersion, k8sVersion, targetAPI) = msg {
  match(targetAPI)
  msg := sprintf("API %v for %v is deprecated in Kubernetes version %v, please see Kubernetes API deprecation guide", [kind, apiVersion, k8sVersion])
}

match(api) {
  api == "None"
}
