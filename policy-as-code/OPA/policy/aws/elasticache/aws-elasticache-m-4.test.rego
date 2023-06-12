package aws.elasticache.m4

msg1 := {"AWS-ElastiCache-M-4: Resource 'aws_elasticache_cluster.not_compliant' engine version is not supported to enable Slow Logs and Engine logs (make sure to use engine version 6.2 or later)."}
msg2 := {"AWS-ElastiCache-M-4: Resource 'aws_elasticache_cluster.not_compliant_slow' should have 'slow-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'slow-log')."}
msg3 := {"AWS-ElastiCache-M-4: Resource 'aws_elasticache_cluster.not_compliant_engine' should have 'engine-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'engine-log')."}
msg4 := {"AWS-ElastiCache-M-4: Resource 'aws_elasticache_cluster.not_compliant_engine_and_slow' should have 'engine-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'engine-log').", "AWS-ElastiCache-M-4: Resource 'aws_elasticache_cluster.not_compliant_engine_and_slow' should have 'slow-log' enabled (make sure to add 'log_delivery_configuration.log_type' for 'slow-log')."}

test_not_compliant{
    result = deny with input as data.mock.not_compliant
    result == msg1
}

test_not_compliant_slow{
    result = deny with input as data.mock.not_compliant_slow
    result == msg2
}

test_not_compliant_engine{
    result = deny with input as data.mock.not_compliant_engine
    result == msg3
}

test_not_compliant_engine_and_slow{
    result = deny with input as data.mock.not_compliant_engine_and_slow
    result == msg4
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
