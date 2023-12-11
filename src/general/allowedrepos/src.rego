package k8sallowedrepos

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not strings.any_prefix_match(container.image, input.parameters.repos)
  msg := sprintf("container <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not strings.any_prefix_match(container.image, input.parameters.repos)
  msg := sprintf("initContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  not strings.any_prefix_match(container.image, input.parameters.repos)
  msg := sprintf("ephemeralContainer <%v> has an invalid image repo <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}
