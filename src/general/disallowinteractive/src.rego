package k8sdisallowinteractivetty

import data.lib.exempt_container.is_exempt

violation[{"msg": msg, "details": {}}] {
    c := input_containers[_]
    not is_exempt(c)
    input_allow_interactive_fields(c)
    msg := sprintf("Containers using tty or stdin (%v) are not allowed running image: %v", [c.name, c.image])
}

input_allow_interactive_fields(c) {
    has_field(c, "stdin")
    not c.stdin == false
}
input_allow_interactive_fields(c) {
    has_field(c, "tty")
    not c.tty == false
}
input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.ephemeralContainers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}
