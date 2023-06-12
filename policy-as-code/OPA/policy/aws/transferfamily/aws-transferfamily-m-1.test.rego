package aws.transferfamily.m1

message = {"AWS-TRANSFER_FAMILY-M-1:TRANSFER_FAMILY protocol should be set to FTPS/SFTP 'aws_transfer_server.example'"}

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
}


test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
}