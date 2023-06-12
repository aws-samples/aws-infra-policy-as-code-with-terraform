package aws.elb.m3

message = {"AWS-ELB-M-3: ELB 'aws_lb.example' should be deployed using internal attribute set to true"}

test_elb_internal_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_elb_internal_undefined {
    result = deny with input as data.mock.undefined
    result == message 
}

test_elb_internal_invalid {
    result = deny with input as data.mock.invalid
    result == message
}
