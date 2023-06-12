package aws.elasticache.m1

# Ensure that Amazon ElastiCache service data must be encrypted in transit.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html

# In-Transit encryption is supported on replication groups running Redis versions 3.2.6, 4.0.10 or later.
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

is_valid_configuration(resource) {
    resource.change.after.engine == "redis"
    is_valid_engine_version(resource)
}

is_transit_encryption_enabled(resource) {
    resource.change.after.transit_encryption_enabled
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_elasticache_replication_group")
    
    not is_valid_configuration(resource)
    message := "AWS-ElastiCache-M-1: Resource '%s' engine version is not supported to enable encryption in transit (make sure to use engine version 3.2.6, 4.0.10 or later)"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_elasticache_replication_group")

    not is_transit_encryption_enabled(resource)
    message := "AWS-ElastiCache-M-1: Resource '%s' should enable encryption in transit (make sure 'transit_encryption_enabled' argument is set to true)"
    reason := sprintf(message, [resource.address])
}
