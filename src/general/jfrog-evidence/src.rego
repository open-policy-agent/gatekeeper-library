package k8sjfrogcheckevidence            
import data.lib.filter_images
import future.keywords.in
import future.keywords.contains

# fails if input.parameters.checkedRegistries is empty
violation[{"msg": msg}] {
    not input.parameters.checkedRegistries
    msg := "checkedRegistries parameter is empty"
}

# fails if input.parameters.checkedPredicateTypes is empty
violation[{"msg": msg}] {
    not input.parameters.checkedPredicateTypes
    msg := "checkedPredicateTypes parameter is empty"
}

# get all images
all_images := [img | img = input.review.object.spec.containers[_].image]
target_images := [img | img = all_images[_]
    filter_images.is_checked_registry(img)
    filter_images.is_checked_repository(img)
]
# get init images
init_images := [img | img = input.review.object.spec.initContainers[_].image]
target_init_images := [img | img = init_images[_]
    filter_images.is_checked_registry(img)
    filter_images.is_checked_repository(img)
]

# append target_images, target_init_images        
checked_images := array.concat(target_images, target_init_images)
# convert arreay input.parameters.checkedPredicateTypes to string
types := concat(",", input.parameters.checkedPredicateTypes)
typesArray := [types]

checked_keys := array.concat(typesArray, checked_images)
violation[{"msg": msg}] {              
    count(checked_images) > 0
    response := external_data({"provider": "jfrog-evidence-opa-provider", "keys": checked_keys})
    any_issues_found(response)
            
    errors_count := count(response.errors)
    system_error := response.system_error
    invalid_images := [img | some item in response.responses
                            count(item) == 2
                            item[1] == "_invalid"
                            img := item[0]]
    msg := sprintf("TARGET IMAGES: %v, ERROR_COUNT: %v, SYSTEM_ERROR: %v, INVALID_IMAGES: %v", [checked_images, errors_count, system_error, invalid_images])
}

any_issues_found(response) {
    count(response.errors) > 0              
} else {
    response.system_error != ""
} else {              
    response_has_invalid(response)
}

response_has_invalid(response) {
    some item in response.responses
    count(item) == 2
    item[1] == "_invalid"
}       

libs:
- |
    package lib.filter_images    
    import future.keywords.in
    is_checked_registry(img) {
        checked_registries := object.get(object.get(input, "parameters", {}), "checkedRegistries", [])
        some registry in checked_registries
        startswith(img, registry)
    }
    is_checked_repository(img) {
        checked_repositories := object.get(object.get(input, "parameters", {}), "checkedRepositories", ["/"])
        some repository in checked_repositories      
        contains(img, repository)
    }