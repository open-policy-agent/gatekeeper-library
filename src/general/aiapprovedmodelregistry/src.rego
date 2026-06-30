package k8saiapprovedmodelregistry

# Require container images to start with an approved model registry prefix.
violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not strings.any_prefix_match(container.image, input.parameters.approvedRegistries)
  msg := sprintf("container <%v> image <%v> is not from an approved model registry; allowed prefixes: %v", [container.name, container.image, input.parameters.approvedRegistries])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not strings.any_prefix_match(container.image, input.parameters.approvedRegistries)
  msg := sprintf("initContainer <%v> image <%v> is not from an approved model registry; allowed prefixes: %v", [container.name, container.image, input.parameters.approvedRegistries])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  not strings.any_prefix_match(container.image, input.parameters.approvedRegistries)
  msg := sprintf("ephemeralContainer <%v> image <%v> is not from an approved model registry; allowed prefixes: %v", [container.name, container.image, input.parameters.approvedRegistries])
}

# Optionally require images to be digest-pinned with @sha256:.
violation[{"msg": msg}] {
  input.parameters.requireDigestPin == true
  container := input.review.object.spec.containers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("container <%v> image <%v> must be digest-pinned (append @sha256:<digest>)", [container.name, container.image])
}

violation[{"msg": msg}] {
  input.parameters.requireDigestPin == true
  container := input.review.object.spec.initContainers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("initContainer <%v> image <%v> must be digest-pinned (append @sha256:<digest>)", [container.name, container.image])
}

violation[{"msg": msg}] {
  input.parameters.requireDigestPin == true
  container := input.review.object.spec.ephemeralContainers[_]
  not contains(container.image, "@sha256:")
  msg := sprintf("ephemeralContainer <%v> image <%v> must be digest-pinned (append @sha256:<digest>)", [container.name, container.image])
}
