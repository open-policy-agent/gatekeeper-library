package lib.exclude_update

import rego.v1

test_update if {
	is_update({"operation": "UPDATE"})
}

test_create if {
	not is_update({"operation": "CREATE"})
}

test_empty if {
	not is_update({"operation": ""})
}
