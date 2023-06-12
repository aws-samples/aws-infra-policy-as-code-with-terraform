package aws.msk.m3

message = {"AWS-MSK-M-3: Kafka version should be above 2.5.1 to ensure Zookeeper encryption for resource 'aws_msk_cluster.cluster'"}

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
} 

test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
}
