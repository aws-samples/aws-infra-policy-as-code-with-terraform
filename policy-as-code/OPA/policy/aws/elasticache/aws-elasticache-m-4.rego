package aws.elasticache.m4

# Ensure that AWS ElastiCache Log Configuration is configured to deliver log events to CloudWatch or Kinesis Data Firehose.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#log-delivery-configuration
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#log-delivery-configuration

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Log_Delivery.html

not_supported_engine_versions = ["6.0","5.0.6","5.0.5","5.0.4","5.0.3","5.0.0","4.0.10","3.2.10", "3.2.4", "2.8.24", "2.8.23", "2.8.22", "2.8.21", "2.8.19", "2.8.6", "2.6.13"]
log_config_supported_resources = ["aws_elasticache_replication_group", "aws_elasticache_cluster"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
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

is_slow_logs_enabled(resource) {
    resource.change.after.log_delivery_configuration[_].log_type == "slow-log"
}

is_engine_logs_enabled(resource){
    resource.change.after.log_delivery_configuration[_].log_type == "engine-log"
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, log_config_supported_resources)
    not is_valid_configuration(resource)
    message := "AWS-ElastiCache-M-4: Resource '%s' engine version is not supported to enable Slow Logs and Engine logs (make sure to use engine version 6.2 or later)."
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, log_config_supported_resources)
    not is_slow_logs_enabled(resource)
    message := "AWS-ElastiCache-M-4: Resource '%s' should have 'slow-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'slow-log')."
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, log_config_supported_resources)
    not is_engine_logs_enabled(resource)
    message := "AWS-ElastiCache-M-4: Resource '%s' should have 'engine-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'engine-log')."
    reason := sprintf(message, [resource.address])
}
