package aws.ec2linux.m1

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	result = deny with input as data.mock.invalid
	result == {"AWS-EC2Linux-M-1: 'module.ec2_module.aws_instance.web' EC2 Linux instance should have 'associate_public_ip_address' parameter set to false"}

}