package aws.pl.m1

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	result = deny with input as data.mock.invalid
	result == {"AWS-PL-M-1: 'aws_vpc_endpoint_service' is used and should have 'acceptance_required' parameter set to true"}

}