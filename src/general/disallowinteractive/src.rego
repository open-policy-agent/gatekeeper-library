package k8sdisallowinteractivetty

import future.keywords.contains
import future.keywords.if

import data.lib.exempt_container.is_exempt

violation contains {"msg": msg, "details": {}} if {
    c := input_containers[_]
    not is_exempt(c)
    input_allow_interactive_fields(c)
    msg := sprintf("Containers using tty or stdin (%v) are not allowed running image: %v", [c.name, c.image])
}

input_allow_interactive_fields(c) if {
    has_field(c, "stdin")
    not c.stdin == false
}

input_allow_interactive_fields(c) if {
    has_field(c, "tty")
    not c.tty == false
}

input_containers contains c if {
    c := input.review.object.spec.containers[_]
}

input_containers contains c if {
    c := input.review.object.spec.ephemeralContainers[_]
}

input_containers contains c if {
    c := input.review.object.spec.initContainers[_]
}

# has_field returns whether an object has a field
has_field(object, field) if {
    object[field]
}
