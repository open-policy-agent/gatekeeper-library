package lib.exempt_container

import future.keywords.contains
import future.keywords.if

test_exact_match_success if {
    is_exempt({"image": "one-two"}) with input.parameters.exemptImages as ["one-two"]
}

test_exact_match_fail if {
    not is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["one-two"]
}

test_prefix_success if {
    is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["one-two-*"]
}

test_prefix_fail if {
    not is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["four-two-*"]
}

test_one_match if {
    is_exempt({"image": "one-two"}) with input.parameters.exemptImages as ["three-four", "one-two"]
}

test_empty_exemption if {
    not is_exempt({"image": "one-two"}) with input.parameters.exemptImages as []
}

test_empty_image if {
    not is_exempt({"image": ""}) with input.parameters.exemptImages as ["three-four", "one-two"]
}

test_no_image if {
    not is_exempt({}) with input.parameters.exemptImages as ["three-four", "one-two"]
}
