package k8srequiredlabels

get_message(parameters, _default) := _default {
  not parameters.message
}

get_message(parameters, _) := parameters.message

violation[{"msg": msg, "details": {"missing_labels": missing}}] {
  provided := {label | input.review.object.metadata.labels[label]}
  required := {label | label := input.parameters.labels[_].key}
  missing := required - provided
  count(missing) > 0
  def_msg := sprintf("you must provide labels: %v", [missing])
  msg := get_message(input.parameters, def_msg)
}

violation[{"msg": msg}] {
  value := input.review.object.metadata.labels[key]
  expected := input.parameters.labels[_]
  expected.key == key
  # do not match if allowedRegex is not defined, or is an empty string
  expected.allowedRegex != ""
  not regex.match(expected.allowedRegex, value)
  def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
  msg := get_message(input.parameters, def_msg)
}
