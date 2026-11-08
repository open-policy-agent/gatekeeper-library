package lib.exclude_update

is_update(review) {
    review.operation == "UPDATE"
    not is_ephemeral_containers_update(review)
}

# Ephemeral containers can only be added with an UPDATE on the
# pods/ephemeralcontainers subresource (kubectl debug). That UPDATE carries
# new containers and must be validated like a CREATE.
is_ephemeral_containers_update(review) {
    review.subResource == "ephemeralcontainers"
}
