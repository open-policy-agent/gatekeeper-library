package k8sdisallowanonymous

violation[{"msg": msg}] {
  not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))

  group := ["system:unauthenticated", "system:anonymous"][_]
  subject_is(input.review.object.subjects[_], group)

  msg := message(group)
}

violation[{"msg": msg}] {
  not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))

  object.get(input, ["parameters", "disallowAuthenticated"], false)

  group := "system:authenticated"
  subject_is(input.review.object.subjects[_], group)

  msg := message(group)
}

is_allowed(role, allowedRoles) {
  role.name == allowedRoles[_]
}

subject_is(subject, expected) {
  subject.name == expected
}

message(name) := val {
  val := sprintf("%v is not allowed as a subject name in %v %v", [name, input.review.object.kind, input.review.object.metadata.name])
}
