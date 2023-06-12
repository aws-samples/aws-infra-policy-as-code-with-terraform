package aws.transferfamily.m3

message = {"AWS-TRANSFER_FAMILY-M-3:TRANSFER_FAMILY Security Policy should be selected either TransferSecurityPolicy-2022-03 or TransferSecurityPolicy-2020-06 'aws_transfer_server.tf_server'"}

test_valid_security_policy {
    result = deny with input as data.mock.valid_security_policy
    count(result) == 0
} 

test_invalid_security_policy {
    result = deny with input as data.mock.invalid_security_policy
    result == message
}