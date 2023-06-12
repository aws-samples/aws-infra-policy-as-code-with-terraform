package aws.efs.m2

msg := {"AWS-EFS-M-2: Resource 'aws_efs_mount_target.alpha' should have security groups defined (make sure 'security_groups' argument is defined) and shall not have '0.0.0.0/0' in inbound rules and only allowed port has to be '2049'"}

test_valid_referenced {
    result = deny with input as data.mock.valid_referenced
    count(result) == 0
}

test_valid_constant {
    result = deny with input as data.mock.valid_constant
    count(result) == 0
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg
}

test_invalid_sg_ref_cidr {
    result = deny with input as data.mock.invalid_sg_ref_cidr
    result == msg
}

test_invalid_sg_ref_cidr2 {
    result = deny with input as data.mock.invalid_sg_ref_cidr2
    result == msg
}
