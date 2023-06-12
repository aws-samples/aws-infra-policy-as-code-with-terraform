package aws.elb.m4

message_listener = {"AWS-ELB-M-4: ELB listener protocol and target group protocol should bet set to HTTPS/TLS 'aws_lb_listener.example'"}  
message_target_group = {"AWS-ELB-M-4: ELB listener protocol and target group protocol should bet set to HTTPS/TLS 'aws_lb_target_group.example'"}

test_valid_https_listener_protocol {
  result = deny with input as data.mock.valid_https_listener_protocol
  count(result) == 0
} 

test_valid_tls_listener_protocol {
  result = deny with input as data.mock.valid_tls_listener_protocol
  count(result) == 0
}

test_valid_https_tg_protocol {
  result = deny with input as data.mock.valid_https_tg_protocol
  count(result) == 0

}

test_valid_tls_tg_protocol {
  result = deny with input as data.mock.valid_tls_tg_protocol
  count(result) == 0

}

test_undefined_listener_protocol {
  result = deny with input as data.mock.undefined_listener_protocol
  result == message_listener
}

test_undefined_tg_protocol {
  result = deny with input as data.mock.undefined_tg_protocol
  result == message_target_group
}

test_invalid_listener_protocol {
  result = deny with input as data.mock.invalid_listener_protocol
  result == message_listener
}

test_invalid_tg_protocol {
  result = deny with input as data.mock.invalid_tg_protocol
  result == message_target_group
}

