package aws.location.m1

# Ensure that AWS Location service geofence collection and tracker are encrypted at rest using AWS KMS CMK.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/location_geofence_collection#kms_key_id
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/location_tracker#kms_key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/location/latest/developerguide/encryption-at-rest.html

encryption_supported_resources = ["aws_location_geofence_collection", "aws_location_tracker"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_kms_key_set(resource) {
    keyId := resource.change.after.kms_key_id
    not is_null(keyId)
    not keyId == ""
    startswith(keyId, "arn:aws:kms:")
} else {
    resource.change.after_unknown.kms_key_id == true
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, encryption_supported_resources)

    not is_kms_key_set(resource)
    message := "AWS-Location-M-1: Resource '%s' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"
    reason := sprintf(message, [resource.address])
}

