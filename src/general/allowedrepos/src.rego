package k8sallowedrepos

# This policy checks Docker image names to ensure they either match the names specified in the constraint file
# or end with a colon (:) for <image-name>:<tag> format
# or with an at symbol (@) for <image-name>@<digest> format
check_image_suffix(image_name, suffix){
  count(image_name) ==  count(suffix)
}

check_image_suffix(image_name,suffix){
  substring(image_name, count(suffix), 1) == ":"
}

check_image_suffix(image_name,suffix){
  substring(image_name, count(suffix), 1) == "@"
}

# This function appends a trailing slash to repository or registry names if one is not already present.
# this enhancement is crucial for security, as it helps prevent attackers from bypassing controls by
# creating subdomains or malicious repositories that begin with the same name as those declared in the constraint file.
# For example, without the slash, a defined registry like fictional.registry.example could be exploited by an attacker
# setting up a malicious registry at fictional.registry.example.malicious.com.
# Similarly, defining a repository as "myrepo" might allow an attacker to bypass restrictions by creating a repository named "myrepoevil" on DockerHub.
ensure_trailing_slash(repo) = result {
    not endswith(repo,"/")
    result := concat("", [repo, "/"])
} else = repo {
    endswith(repo,"/")
}

# Define array of all repositories or registries with a trailing slash.
processed_repos := [ensure_trailing_slash(repo) | repo := input.parameters.repos[_]]
processed_images := [image | image := input.parameters.images[_]]

# Create array for images with and without a slash.
imagesWithSlash := [image | image := input.parameters.images[_]; contains(image, "/")]
imagesWithoutSlash := [image | image := input.parameters.images[_]; not contains(image, "/")]

# Concatenate user-defined repositories and registries with images to define permitted sources
permitted_sources = array.concat(processed_repos, processed_images)

# Check whether the given user input is a valid Docker image.
check_image_policy(container_image)
{
    not contains(container_image, "/")
    matching_prefixes := {prefix |
    prefix := imagesWithoutSlash[_]  # Iterate over each prefix in the list
    startswith(container_image, prefix)  # Check if the container_image starts with this prefix
    check_image_suffix(container_image,prefix)
    }

    not count(matching_prefixes) == 0
}

check_image_policy(container_image)
{
    matching_prefixes := {prefix |
    prefix := imagesWithSlash[_]  # Iterate over each prefix in the list
    startswith(container_image, prefix)  # Check if the container_image starts with this prefix
    check_image_suffix(container_image,prefix)
    }
  
    not count(matching_prefixes) == 0
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not strings.any_prefix_match(container.image, processed_repos)
  not check_image_policy(container.image)
  msg := sprintf("container <%v> has an invalid image source <%v>, allowed sources are <%v>", [container.name, container.image, permitted_sources])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  not strings.any_prefix_match(container.image, processed_repos)
  not check_image_policy(container.image)
  msg := sprintf("initContainer <%v> has an invalid image source <%v>, allowed sources are <%v> ", [container.name, container.image, permitted_sources])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.ephemeralContainers[_]
  not strings.any_prefix_match(container.image, processed_repos)
  not check_image_policy(container.image)
  msg := sprintf("ephemeralContainer <%v> has an invalid source repo <%v>, allowed sources are <%v>", [container.name, container.image, permitted_sources])
}