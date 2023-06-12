package aws.quicksight.m2

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	result = deny with input as data.mock.invalid
	result == {"AWS-QuickSight-M-2: 'aws_quicksight_data_source' is used and should have 'vpc_connection_arn' property set to arn of the connection"}
}
