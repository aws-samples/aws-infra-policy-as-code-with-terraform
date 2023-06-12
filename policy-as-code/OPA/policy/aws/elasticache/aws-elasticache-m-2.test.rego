package aws.elasticache.m2

msg := {"AWS-ElastiCache-M-2: Resource 'aws_elasticache_replication_group.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}
msg2 := {"AWS-ElastiCache-M-2: Resource 'aws_elasticache_replication_group.test' engine version is not supported to enable encryption at rest (make sure to use engine version 3.2.6, 4.0.10 or later)", "AWS-ElastiCache-M-2: Resource 'aws_elasticache_replication_group.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}
msg3 := {"AWS-ElastiCache-M-2: Resource 'aws_elasticache_replication_group.test' should have at_rest_encryption_enabled to define kms_key_id (make sure 'at_rest_encryption_enabled' is set to 'true')", "AWS-ElastiCache-M-2: Resource 'aws_elasticache_replication_group.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}

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

test_invalid_kms_key {
    result = deny with input as data.mock.invalid_kms_key
    result == msg
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg3
}
