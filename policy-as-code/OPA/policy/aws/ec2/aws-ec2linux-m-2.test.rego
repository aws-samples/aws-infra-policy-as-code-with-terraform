package aws.ec2linux.m2

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid_optional {
	result = deny with input as data.mock.invalid_optional
	result == {"AWS-EC2Linux-M-2: 'module.ec2_module.aws_instance.web' EC2 Linux instance should have 'http_tokens' parameter set to required"}

}

test_invalid_no_metadata {
	result = deny with input as data.mock.invalid_no_metadata
	result == {"AWS-EC2Linux-M-2: 'module.ec2_module.aws_instance.web' EC2 Linux instance should have 'http_tokens' parameter set to required"}

}