package aws.lambda.r1

msg = "AWS-Lambda-R-1: Lambda 'aws_lambda_function.test_lambda' environment variables should be encrypted with customer managed keys (CMK) (make sure 'kms_key_arn' argument is set)"

test_valid_concrete_key_value {
	result = deny with input as data.mock.valid.concrete_key_value
	count(result) == 0
}

test_valid_key_resource_reference {
	result = deny with input as data.mock.valid.key_resource_reference
	count(result) == 0
}

test_valid_environment_variables_not_used {
	result = deny with input as data.mock.valid.environment_variables_not_used
	count(result) == 0
}

test_key_missing {
	result = deny with input as data.mock.invalid.key_missing
	count(result) == 1
    result[msg]
}

test_key_empty {
	result = deny with input as data.mock.invalid.key_empty
	count(result) == 1
    result[msg]
}
