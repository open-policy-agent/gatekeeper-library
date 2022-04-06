package k8srequiredresources

import data.lib.exempt_container.is_exempt

violation[{"msg": msg}] {
  general_violation[{"msg": msg, "field": "containers"}]
}

violation[{"msg": msg}] {
  general_violation[{"msg": msg, "field": "initContainers"}]
}

general_violation[{"msg": msg, "field": field}] {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  provided := {resource_type | container.resources.limits[resource_type]}
  required := {resource_type | resource_type := input.parameters.limits[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("container <%v> does not have <%v> limits defined", [container.name, missing])
}

general_violation[{"msg": msg, "field": field}] {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  provided := {resource_type | container.resources.requests[resource_type]}
  required := {resource_type | resource_type := input.parameters.requests[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("container <%v> does not have <%v> requests defined", [container.name, missing])
}
