package aws.efs.m1

# Ensure that Amazon EFS file systems are encrypted at rest using AWS KMS CMK.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system#kms_key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html

supported_resource_types = ["aws_efs_file_system"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_encrypted_enabled(resource) {
    resource.change.after.encrypted
} else = false {
    true
}

is_kms_key_set(resource) {
    config_resource := data.utils.find_configuration_resource(input, resource)
    key_id := config_resource.expressions.kms_key_id.constant_value
    not is_null(key_id)
    not key_id == ""
    startswith(key_id, "arn:aws:kms:")
} else {
    config_resource := data.utils.find_configuration_resource(input, resource)
    key_refs := config_resource.expressions.kms_key_id.references
    count(key_refs) > 0
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, supported_resource_types)

    not is_encrypted_enabled(resource)
    message := "AWS-EFS-M-1: Resource '%s' should have 'encrypted' argument set to 'true' to use customer managed keys (CMK) (make sure 'encrypted' argument is set to 'true')"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, supported_resource_types)

    not is_kms_key_set(resource)
    message := "AWS-EFS-M-1: Resource '%s' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"
    reason := sprintf(message, [resource.address])
}
