package k8spspselinux

# Disallow top level custom SELinux options
violation[{"msg": msg, "details": {}}] {
    accept_context(input.parameters.seLinuxContext, input.review.object.spec.securityContext)
    msg := sprintf("SELinux options is not allowed, pod: %v. Allowed options: %v", [input.review.object.metadata.name, input.parameters.allowedSELinuxOptions])
}
# Disallow container level custom SELinux options
violation[{"msg": msg, "details": {}}] {
    c := input_security_context[_]
    accept_context(input.parameters.seLinuxContext, c.securityContext)
    msg := sprintf("SELinux options is not allowed, pod: %v, container %v. Allowed options: %v", [input.review.object.metadata.name, c.name, input.parameters.allowedSELinuxOptions])
}

input_seLinuxOptions_allowed(options) {
    params := input.parameters.allowedSELinuxOptions[_]
    field_allowed("level", options, params)
    field_allowed("role", options, params)
    field_allowed("type", options, params)
    field_allowed("user", options, params)
}

field_allowed(field, options, params) {
    params[field] == options[field]
}
field_allowed(field, options, params) {
    not has_field(options, field)
}

input_security_context[c] {
    c := input.review.object.spec.containers[_]
    has_field(c.securityContext, "seLinuxOptions")
}
input_security_context[c] {
    c := input.review.object.spec.initContainers[_]
    has_field(c.securityContext, "seLinuxOptions")
}

# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}

accept_context(rule, context) = false {
  rule == "RunAsAny"
}

accept_context(rule, context) = true {
  rule == "MustRunAs"
  has_field(context, "seLinuxOptions")
  not input_seLinuxOptions_allowed(context.seLinuxOptions)
}
