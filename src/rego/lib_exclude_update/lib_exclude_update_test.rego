package lib.exclude_update

import future.keywords.contains
import future.keywords.if

test_update if {
    is_update({"operation": "UPDATE"})
}

test_create if {
    not is_update({"operation": "CREATE"})
}

test_empty if {
    not is_update({"operation": ""})
}
