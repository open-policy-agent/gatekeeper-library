package k8simagedigests

import future.keywords.contains
import future.keywords.if

import data.lib.exempt_container.is_exempt

violation contains ({"msg": msg}) if {
  container := input.review.object.spec.containers[_]
  not is_exempt(container)
  not regex.match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)
  msg := sprintf("container <%v> uses an image without a digest <%v>", [container.name, container.image])
}

violation contains ({"msg": msg}) if {
  container := input.review.object.spec.initContainers[_]
  not is_exempt(container)
  not regex.match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)
  msg := sprintf("initContainer <%v> uses an image without a digest <%v>", [container.name, container.image])
}

violation contains ({"msg": msg}) if {
  container := input.review.object.spec.ephemeralContainers[_]
  not is_exempt(container)
  not regex.match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)
  msg := sprintf("ephemeralContainer <%v> uses an image without a digest <%v>", [container.name, container.image])
}
