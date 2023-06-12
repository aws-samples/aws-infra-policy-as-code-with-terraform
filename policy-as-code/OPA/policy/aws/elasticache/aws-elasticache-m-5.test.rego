package aws.elasticache.m5

msg := {"AWS-ElastiCache-M-5: Resource 'aws_elasticache_replication_group.test' should send cluster events to SNS topic (make sure 'notification_topic_arn' argument is set)"}

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
    result == msg
}
