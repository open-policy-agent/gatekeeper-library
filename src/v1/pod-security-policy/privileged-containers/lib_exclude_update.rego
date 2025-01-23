package lib.exclude_update

import rego.v1

is_update(review) if {
	review.operation == "UPDATE"
}
