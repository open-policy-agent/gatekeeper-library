package k8srequiredannotations

violation[{"msg": msg, "details": {"missing_annotations": missing}}] {
    provided := {annotation | input.review.object.metadata.annotations[annotation]}
    required := {annotation | annotation := input.parameters.annotations[_].key}
    missing := required - provided
    count(missing) > 0
    msg := sprintf("you must provide annotation(s): %v", [missing])
}

violation[{"msg": msg}] {
  value := input.review.object.metadata.annotations[key]
  expected := input.parameters.annotations[_]
  expected.key == key
  expected.allowedRegex != ""
  not regex.match(expected.allowedRegex, value)
  msg := sprintf("Annotation <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
}
