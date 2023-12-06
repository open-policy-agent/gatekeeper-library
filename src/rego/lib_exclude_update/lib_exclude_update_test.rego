package lib.exclude_update

test_update {
    is_update({"operation": "UPDATE"})
}

test_create {
    not is_update({"operation": "CREATE"})
}

test_empty {
    not is_update({"operation": ""})
}
