package k8sdisallowanonymous

violation[{"msg": msg}] {
  not is_allowed(input.review.object.roleRef, input.parameters.allowedRoles)
  review(input.review.object.subjects[_])
  msg := sprintf("Unauthenticated user reference is not allowed in %v %v ", [input.review.object.kind, input.review.object.metadata.name])
}

is_allowed(role, allowedRoles) {
  role.name == allowedRoles[_]
}

review(subject) = true {
  subject.name == "system:unauthenticated"
}

review(subject) = true {
  subject.name == "system:anonymous"
}
