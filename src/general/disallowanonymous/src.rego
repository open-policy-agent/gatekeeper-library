package k8sdisallowanonymous

import future.keywords.contains
import future.keywords.if

violation contains ({"msg": msg}) if {
  not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))

  group := ["system:unauthenticated", "system:anonymous"][_]
  subject_is(input.review.object.subjects[_], group)

  msg := message(group)
}

violation contains ({"msg": msg}) if {
  not is_allowed(input.review.object.roleRef, object.get(input, ["parameters", "allowedRoles"], []))

  object.get(input, ["parameters", "disallowAuthenticated"], false)

  group := "system:authenticated"
  subject_is(input.review.object.subjects[_], group)

  msg := message(group)
}

is_allowed(role, allowedRoles) if {
  role.name == allowedRoles[_]
}

subject_is(subject, expected) if {
  subject.name == expected
}

message(name) := val if {
  val := sprintf("%v is not allowed as a subject name in %v %v", [name, input.review.object.kind, input.review.object.metadata.name])
}
