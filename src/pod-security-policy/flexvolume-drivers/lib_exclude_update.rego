package lib.exclude_update

import future.keywords.in

is_update(review) {
    review.operation == "UPDATE"
}
