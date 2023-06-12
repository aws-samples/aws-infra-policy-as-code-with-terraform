package aws.msk.m2

message = {"AWS-MSK-M-2: MSK cluster 'aws_msk_cluster.cluster' should use a CMK"}

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
}

test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
} 