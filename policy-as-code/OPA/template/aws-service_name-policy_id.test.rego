package aws.cloudwservice_name.check_number

test_valid_concrete_key_value {
	result = deny with input as data.mock.valid.1st_policy_check
	count(result) == 0
}

test_valid_key_resource_reference {
	result = deny with input as data.mock.valid.2nd_policy_check
	count(result) == 0
}


test_key_missing {
	result = deny with input as data.mock.invalid.1st_policy_invalid_check
	count(result) == 1
    result["AWS-service_name-check_number: what is wrong"]
}

test_key_empty {
	result = deny with input as data.mock.invalid.2nd_policy_invalid_check
	count(result) == 1
    result["AWS-service_name-check_number: what is wrong"]
}
