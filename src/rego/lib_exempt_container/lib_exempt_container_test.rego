package lib.exempt_container

test_exact_match_success {
    is_exempt({"image": "one-two"}) with input.parameters.exemptImages as ["one-two"]
}

test_exact_match_fail {
    not is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["one-two"]
}

test_prefix_success {
    is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["one-two-*"]
}

test_prefix_fail {
    not is_exempt({"image": "one-two-three"}) with input.parameters.exemptImages as ["four-two-*"]
}

test_one_match {
    is_exempt({"image": "one-two"}) with input.parameters.exemptImages as ["three-four", "one-two"]
}

test_empty_exemption {
    not is_exempt({"image": "one-two"}) with input.parameters.exemptImages as []
}

test_empty_image {
    not is_exempt({"image": ""}) with input.parameters.exemptImages as ["three-four", "one-two"]
}

test_no_image {
    not is_exempt({}) with input.parameters.exemptImages as ["three-four", "one-two"]
}
