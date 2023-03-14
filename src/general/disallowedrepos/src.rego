package k8sdisallowedrepos

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  image := container.image
  startswith(image, input.parameters.repos[_])
  msg := sprintf("container <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  image := container.image
  startswith(image, input.parameters.repos[_])
  msg := sprintf("initContainer <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  image := container.image
  startswith(image, input.parameters.repos[_])
  msg := sprintf("ephemeralContainer <%v> has an invalid image repo <%v>, disallowed repos are %v", [container.name, container.image, input.parameters.repos])
}
