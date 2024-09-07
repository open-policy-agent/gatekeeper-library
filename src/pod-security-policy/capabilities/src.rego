package capabilities

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
  # spec.containers.securityContext.capabilities field is immutable.
  not is_update(input.review)

  container := input.review.object.spec.containers[_]
  not is_exempt(container)
  has_disallowed_capabilities(container)
  msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
}

violation[{"msg": msg}] {
  not is_update(input.review)
  container := input.review.object.spec.containers[_]
  not is_exempt(container)
  missing_drop_capabilities(container)
  msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
}

violation[{"msg": msg}] {
  not is_update(input.review)
  container := input.review.object.spec.initContainers[_]
  not is_exempt(container)
  has_disallowed_capabilities(container)
  msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
}

violation[{"msg": msg}] {
  not is_update(input.review)
  container := input.review.object.spec.initContainers[_]
  not is_exempt(container)
  missing_drop_capabilities(container)
  msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
}

violation[{"msg": msg}] {
  not is_update(input.review)
  container := input.review.object.spec.ephemeralContainers[_]
  not is_exempt(container)
  has_disallowed_capabilities(container)
  msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
}

violation[{"msg": msg}] {
  not is_update(input.review)
  container := input.review.object.spec.ephemeralContainers[_]
  not is_exempt(container)
  missing_drop_capabilities(container)
  msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
}

has_disallowed_capabilities(container) {
  allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
  not allowed["*"]
  capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

  count(capabilities - allowed) > 0
}

missing_drop_capabilities(container) {
  must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
  all := {"all"}
  dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

  count(must_drop - dropped) > 0
  count(all - dropped) > 0
}

get_default(obj, param, _) := obj[param]

get_default(obj, param, _default) := _default {
  not obj[param]
  not obj[param] == false
}
