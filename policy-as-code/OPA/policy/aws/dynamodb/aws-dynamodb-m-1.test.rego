package aws.dynamodb.m1

test_valid_cmk_string {
	result = deny with input as data.mock.valid.cmk
	count(result) == 0
}
test_valid_cmk_reference {
	result = deny with input as data.mock.valid.cmk_reference
	count(result) == 0
}
test_no_enc {
	result = deny with input as data.mock.invalid.no_enc
	result == {"AWS-DynamoDB-M-1: Resource 'aws_dynamodb_table.basic-dynamodb-table2' kms_key_arn must be set to CMK ARN"}
}
