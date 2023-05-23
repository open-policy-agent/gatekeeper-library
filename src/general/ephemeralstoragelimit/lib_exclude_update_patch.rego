package lib.exclude_update_patch

import future.keywords.in

is_update_or_patch(review) {
    review.operation in ["UPDATE", "PATCH"]
}
