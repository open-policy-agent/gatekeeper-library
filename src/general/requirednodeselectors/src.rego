package k8srequirednodeselectors

violation[{"msg": msg}] {
    required := input.parameters.nodeSelectors[_]
    not input.review.object.spec.nodeSelector[required]
    msg := sprintf("Pod spec must specify the following node selectors: %v", [input.parameters.nodeSelectors])
}