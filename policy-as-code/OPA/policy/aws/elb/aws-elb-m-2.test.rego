package aws.elb.m2

message = {"AWS-ELB-M-2: ELB target group 'aws_lb_target_group.example_tg' should be configured with connection_termination set to false"}

test_tg_conn_termination_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_tg_conn_termination_invalid {
    result = deny with input as data.mock.invalid
    result == message
}

test_tg_conn_termination_undefined {
    result = deny with input as data.mock.undefined
    count(result) == 0 
}
