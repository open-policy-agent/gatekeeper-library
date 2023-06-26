package k8srequiredannotations

import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
  input.review.kind.kind != "Pod"
  provided := {annotation | input.review.object.metadata.annotations[annotation]}
  required := {annotation | annotation := input.parameters.annotations[_].key}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("you must provide annotation(s): %v", [missing])
}

violation[{"msg": msg}] {
  input.review.kind.kind != "Pod"
  value := input.review.object.metadata.annotations[key]
  expected := input.parameters.annotations[_]
  expected.key == key
  expected.allowedRegex != ""
  not re_match(expected.allowedRegex, value)
  msg := sprintf("Annotation <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
}

violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
  input.review.kind.kind == "Pod"
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  provided := {annotation | input.review.object.metadata.annotations[annotation]}
  required := {annotation | annotation := input.parameters.annotations[_].key}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("you must provide annotation(s): %v", [missing])
}

violation[{"msg": msg}] {
  input.review.kind.kind == "Pod"
  container := input.review.object.spec[field][_]
  not is_exempt(container)
  value := input.review.object.metadata.annotations[key]
  expected := input.parameters.annotations[_]
  expected.key == key
  expected.allowedRegex != ""
  not re_match(expected.allowedRegex, value)
  msg := sprintf("Annotation <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
}
