package lib.exclude_update

import future.keywords.contains
import future.keywords.if

is_update(review) if {
    review.operation == "UPDATE"
}
