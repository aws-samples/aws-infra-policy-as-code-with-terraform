package aws.elasticache.m3

msg := {"AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' should use Role-Based Access control (RBAC) authentication instead of Redis AUTH access (make sure 'user_group_ids' argument is set)"}
msg2 := {"AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' engine version is not supported to enable encryption in transit (make sure to use engine version 3.2.6, 4.0.10 or later)", "AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' should enable encryption in transit to set RBAC authentication (make sure 'transit_encryption_enabled' argument is set to true)", "AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' should use Role-Based Access control (RBAC) authentication instead of Redis AUTH access (make sure 'user_group_ids' argument is set)"}
msg3 := {"AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' should enable encryption in transit to set RBAC authentication (make sure 'transit_encryption_enabled' argument is set to true)", "AWS-ElastiCache-M-3: Resource 'aws_elasticache_replication_group.test' should use Role-Based Access control (RBAC) authentication instead of Redis AUTH access (make sure 'user_group_ids' argument is set)"}

test_valid_referenced {
    result = deny with input as data.mock.valid_referenced
    count(result) == 0
}

test_valid_constant {
    result = deny with input as data.mock.valid_constant
    count(result) == 0
}

test_invalid_engine_version {
    result = deny with input as data.mock.invalid_engine_version
    result == msg2
}

test_invalid_user_group_id {
    result = deny with input as data.mock.invalid_user_group_id
    result == msg
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg3
}
