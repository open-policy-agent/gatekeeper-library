package k8scontainerephemeralstoragelimit

import future.keywords.contains
import future.keywords.if

import data.lib.exclude_update.is_update
import data.lib.exempt_container.is_exempt

missing(obj, field) if {
  not obj[field]
}

missing(obj, field) if {
  obj[field] == ""
}

has_field(object, field) if {
    object[field]
}

# 10 ** 21
storage_multiple("E") := 1000000000000000000000

# 10 ** 18
storage_multiple("P") := 1000000000000000000

# 10 ** 15
storage_multiple("T") := 1000000000000000

# 10 ** 12
storage_multiple("G") := 1000000000000

# 10 ** 9
storage_multiple("M") := 1000000000

# 10 ** 6
storage_multiple("k") := 1000000

# 10 ** 3
storage_multiple("") := 1000

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
storage_multiple("m") := 1

# 1000 * 2 ** 10
storage_multiple("Ki") := 1024000

# 1000 * 2 ** 20
storage_multiple("Mi") := 1048576000

# 1000 * 2 ** 30
storage_multiple("Gi") := 1073741824000

# 1000 * 2 ** 40
storage_multiple("Ti") := 1099511627776000

# 1000 * 2 ** 50
storage_multiple("Pi") := 1125899906842624000

# 1000 * 2 ** 60
storage_multiple("Ei") := 1152921504606846976000

get_suffix(storage) := suffix if {
  not is_string(storage)
  suffix := ""
}

get_suffix(storage) := suffix if {
  is_string(storage)
  count(storage) > 0
  suffix := substring(storage, count(storage) - 1, -1)
  storage_multiple(suffix)
}

get_suffix(storage) := suffix if {
  is_string(storage)
  count(storage) > 1
  suffix := substring(storage, count(storage) - 2, -1)
  storage_multiple(suffix)
}

get_suffix(storage) := suffix if {
  is_string(storage)
  count(storage) > 1
  not storage_multiple(substring(storage, count(storage) - 1, -1))
  not storage_multiple(substring(storage, count(storage) - 2, -1))
  suffix := ""
}

get_suffix(storage) := suffix if {
  is_string(storage)
  count(storage) == 1
  not storage_multiple(substring(storage, count(storage) - 1, -1))
  suffix := ""
}

get_suffix(storage) := suffix if {
  is_string(storage)
  count(storage) == 0
  suffix := ""
}

canonify_storage(orig) := new if {
  is_number(orig)
  new := orig * 1000
}

canonify_storage(orig) := new if {
  not is_number(orig)
  suffix := get_suffix(orig)
  raw := replace(orig, suffix, "")
  regex.match("^[0-9]+(\\.[0-9]+)?$", raw)
  new := to_number(raw) * storage_multiple(suffix)
}

violation contains ({"msg": msg}) if {

  # spec.containers.resources.limits["ephemeral-storage"] field is immutable.
  not is_update(input.review)

  general_violation[{"msg": msg, "field": "containers"}]
}

violation contains ({"msg": msg}) if {
  not is_update(input.review)
  general_violation[{"msg": msg, "field": "initContainers"}]
}

# Ephemeral containers not checked as it is not possible to set field.

general_violation contains {"msg": msg, "field": field} if {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  storage_orig := container.resources.limits["ephemeral-storage"]
  not canonify_storage(storage_orig)
  msg := sprintf("container <%v> ephemeral-storage limit <%v> could not be parsed", [container.name, storage_orig])
}

general_violation contains {"msg": msg, "field": field} if {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  not container.resources
  msg := sprintf("container <%v> has no resource limits", [container.name])
}

general_violation contains {"msg": msg, "field": field} if {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  not container.resources.limits
  msg := sprintf("container <%v> has no resource limits", [container.name])
}

general_violation contains {"msg": msg, "field": field} if {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  missing(container.resources.limits, "ephemeral-storage")
  msg := sprintf("container <%v> has no ephemeral-storage limit", [container.name])
}

general_violation contains {"msg": msg, "field": field} if {
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  storage_orig := container.resources.limits["ephemeral-storage"]
  storage := canonify_storage(storage_orig)
  max_storage_orig := input.parameters["ephemeral-storage"]
  max_storage := canonify_storage(max_storage_orig)
  storage > max_storage
  msg := sprintf("container <%v> ephemeral-storage limit <%v> is higher than the maximum allowed of <%v>", [container.name, storage_orig, max_storage_orig])
}
