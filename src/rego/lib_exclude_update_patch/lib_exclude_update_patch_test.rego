package lib.exclude_update_patch

test_update {
    is_update_or_patch({"operation": "UPDATE"})
}

test_patch {
    is_update_or_patch({"operation": "PATCH"})
}

test_create {
    not is_update_or_patch({"operation": "CREATE"})
}

test_empty {
    not is_update_or_patch({"operation": ""})
}
