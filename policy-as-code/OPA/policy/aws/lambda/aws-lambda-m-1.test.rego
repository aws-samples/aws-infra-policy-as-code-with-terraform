package aws.lambda.m1

test_valid_deny_policy {
	result = deny with input as data.mock.valid.deny_policy
	count(result) == 0
}

test_valid_allow_policy {
	result = deny with input as data.mock.valid.allow_policy
	count(result) == 0
}

test_full_access_policy {
	result = deny with input as data.mock.invalid.full_access_policy
	count(result) == 1
    result["AWS-Lambda-M-1: VPC Endpoint 'aws_vpc_endpoint.lambda' policy should restrict traffic to functions within own AWS account (use 'aws:PrincipalAccount' condition key)"]
}

test_no_policy {
	result = deny with input as data.mock.invalid.no_policy
	count(result) == 1
    result["AWS-Lambda-M-1: VPC Endpoint 'aws_vpc_endpoint.lambda' has no policy (you must attach a policy and restrict access to the same account)"]
}
