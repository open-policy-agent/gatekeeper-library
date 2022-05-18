package k8simagedigests

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not is_exempt(container)
  satisfied := [re_match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)]
  not all(satisfied)
  msg := sprintf("container <%v> uses an image without a digest <%v>", [container.name, container.image])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not is_exempt(container)
  satisfied := [re_match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)]
  not all(satisfied)
  msg := sprintf("initContainer <%v> uses an image without a digest <%v>", [container.name, container.image])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  not is_exempt(container)
  satisfied := [re_match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)]
  not all(satisfied)
  msg := sprintf("ephemeralContainer <%v> uses an image without a digest <%v>", [container.name, container.image])
}
