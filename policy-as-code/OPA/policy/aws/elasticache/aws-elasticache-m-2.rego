package aws.elasticache.m2

# Ensure that Amazon ElastiCache service data are encrypted at rest using AWS CMK.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#at_rest_encryption_enabled
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#kms_key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html#using-customer-managed-keys-for-elasticache-security

# At-rest encryption is supported on replication groups running Redis versions 3.2.6, 4.0.10 or later.
not_supported_engine_versions = ["3.2.10", "3.2.4", "2.8.24", "2.8.23", "2.8.22", "2.8.21", "2.8.19", "2.8.6", "2.6.13"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, type){
    resource.mode == "managed"
    resource.type == type
    data.utils.is_resource_create_or_update(resource)
}

is_engine_version_defined(resource, name){
    not resource[name]
}

is_valid_engine_version(resource){
    is_engine_version_defined(resource.change.after, "engine_version")
    resource.change.after_unknown.engine_version
} else {
    not data.utils.includes(not_supported_engine_versions, resource.change.after.engine_version)
} else = false {
    true
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

is_valid_configuration(resource) {
    resource.change.after.engine == "redis"
    is_valid_engine_version(resource)
}

is_at_rest_encryption_enabled(resource) {
    resource.change.after.at_rest_encryption_enabled
}


# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_elasticache_replication_group")
    
    not is_valid_configuration(resource)
    message := "AWS-ElastiCache-M-2: Resource '%s' engine version is not supported to enable encryption at rest (make sure to use engine version 3.2.6, 4.0.10 or later)"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_elasticache_replication_group")

    not is_at_rest_encryption_enabled(resource)
    message := "AWS-ElastiCache-M-2: Resource '%s' should have at_rest_encryption_enabled to define kms_key_id (make sure 'at_rest_encryption_enabled' is set to 'true')"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_elasticache_replication_group")

    not is_kms_key_set(resource)
    message := "AWS-ElastiCache-M-2: Resource '%s' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"
    reason := sprintf(message, [resource.address])
}
