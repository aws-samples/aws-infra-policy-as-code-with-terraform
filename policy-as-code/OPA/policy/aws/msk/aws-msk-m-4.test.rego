package aws.msk.m4

message = {"AWS-MSK-M-4: Authentication should be set to IAM for 'aws_msk_cluster.cluster'"} 

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
} 

test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
}
