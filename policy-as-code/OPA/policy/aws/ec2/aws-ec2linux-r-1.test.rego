package aws.ec2linux.r1

test_valid_sg_by_ref {
    result = deny with input as data.mock.valid.sg_by_ref
    count(result) == 0
}

test_valid_sg_by_id {
    result = deny with input as data.mock.valid.sg_by_id
    count(result) == 0
}

test_valid_flat_sg_by_ref {
    result = deny with input as data.mock.valid.flat_sg_by_ref
    count(result) == 0
}

test_invalid_open_rule{
    result = deny with input as data.mock.invalid.open_rule
    msg = {"AWS-EC2Linux-R-1: EC2 resource 'aws_instance' security groups shall not have '0.0.0.0/0' in inbound rules"}
    result == msg
}

test_invalid_no_sg{
    result = deny with input as data.mock.invalid.no_sg
    msg = {"AWS-EC2Linux-R-1: EC2 resource 'aws_instance' must have security groups attached"}
    result == msg
}
