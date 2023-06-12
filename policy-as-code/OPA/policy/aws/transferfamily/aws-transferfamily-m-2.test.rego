package aws.transferfamily.m2

message = {"AWS-TRANSFER_FAMILY-M-2:TRANSFER_FAMILY Identity Provider should be selected as API Gateway, AWS LAMBDA or AWS DIRECTORY SERVICE 'aws_transfer_server.tf_server'"}

test_valid_protocol {
    result = deny with input as data.mock.valid_identity_provider
    count(result) == 0
} 

test_invalid_protocol {
    result = deny with input as data.mock.invalid_identity_provider
    result == message
}
