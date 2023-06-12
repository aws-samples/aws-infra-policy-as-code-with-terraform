package aws.elb.m1

message = {"AWS-ELB-M-1: ELB should have access_logs enabled for 'aws_lb.lb_example'"}

test_elb_access_logging_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_elb_access_logging_undefined {
	result = deny with input as data.mock.undefined
	result == message
}

test_elb_access_logging_invalid {
	result = deny with input as data.mock.invalid
	result == message
}
