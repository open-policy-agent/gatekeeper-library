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

test_ephemeral_containers_update {
    not is_update({"operation": "UPDATE", "subResource": "ephemeralcontainers"})
}

test_other_subresource_update {
    is_update({"operation": "UPDATE", "subResource": "status"})
}
