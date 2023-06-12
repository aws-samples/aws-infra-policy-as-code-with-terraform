package aws.dynamodb.m3

test_valid {
	result = deny with input as data.mock.valid.encrypted
	count(result) == 0
}
test_no_TLS {
	result = deny with input as data.mock.invalid.no_TLS
	result == {"AWS-DynamoDB-M-3: Resource 'aws_dax_cluster.not_encrypted' cluster_endpoint_encryption_type must be set to TLS"}
}
test_no_ServerSide {
	result = deny with input as data.mock.invalid.no_ServerSide
	result == {"AWS-DynamoDB-M-3: Resource 'aws_dax_cluster.not_encrypted' Server Side Encryption must be enabled"}
}
test_no_Both {
	result = deny with input as data.mock.invalid.no_Both
	result == {
		"AWS-DynamoDB-M-3: Resource 'aws_dax_cluster.not_encrypted' Server Side Encryption must be enabled", 
		"AWS-DynamoDB-M-3: Resource 'aws_dax_cluster.not_encrypted' cluster_endpoint_encryption_type must be set to TLS"
	}
}
