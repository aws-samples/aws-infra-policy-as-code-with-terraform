package aws.elasticache.m1

msg := {"AWS-ElastiCache-M-1: Resource 'aws_elasticache_replication_group.test' should enable encryption in transit (make sure 'transit_encryption_enabled' argument is set to true)"}
msg2 := {"AWS-ElastiCache-M-1: Resource 'aws_elasticache_replication_group.test' engine version is not supported to enable encryption in transit (make sure to use engine version 3.2.6, 4.0.10 or later)", "AWS-ElastiCache-M-1: Resource 'aws_elasticache_replication_group.test' should enable encryption in transit (make sure 'transit_encryption_enabled' argument is set to true)"}


test_valid_referenced {
    result = deny with input as data.mock.valid_referenced
    count(result) == 0
}

test_valid_constant {
    result = deny with input as data.mock.valid_constant
    count(result) == 0
}

test_invalid {
    result = deny with input as data.mock.invalid
    result == msg2
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg
}
