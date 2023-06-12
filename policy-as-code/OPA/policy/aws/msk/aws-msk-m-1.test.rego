package aws.msk.m1

message = {"AWS-MSK-M-1: Protocol should be set to TLS for encryption_in_transit.client_broker for resource 'aws_msk_cluster.cluster'"} 

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
} 

test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
}

test_undefined_protocol {
  result = deny with input as data.mock.undefined_protocol
  result == message
}