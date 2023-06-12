package aws.transferfamily.m4

message = {"AWS-TRANSFER_FAMILY-M-4:TRANSFER_FAMILY Endpoint Type should be selected as VPC and Public IP must be blocked 'aws_transfer_server.tf_server'"}

test_valid_endpoint_type {
  result = deny with input as data.mock.valid_endpoint_type
  count(result) == 0
} 


test_invalid_endpoint_type_internet {
  result = deny with input as data.mock.invalid_endpoint_type_internet
  result == message
}

test_invalid_endpoint_type_public {
  result = deny with input as data.mock.invalid_endpoint_type_public
  result == message
}

test_invalid_endpoint_type_vpc_endpont {
  result = deny with input as data.mock.invalid_endpoint_type_vpc_endpont
  result == message
}