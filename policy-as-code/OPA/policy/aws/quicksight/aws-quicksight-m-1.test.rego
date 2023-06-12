package aws.quicksight.m1

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid_no_ssl {
	result = deny with input as data.mock.invalid.no_ssl
	result == {"AWS-QuickSight-M-1: 'aws_quicksight_data_source' is used and should have 'disable_ssl' property set to false"}
}

test_invalid_ssl_disabled {
	result = deny with input as data.mock.invalid.ssl_disabled
	result == {"AWS-QuickSight-M-1: 'aws_quicksight_data_source' is used and should have 'disable_ssl' property set to false"}
}