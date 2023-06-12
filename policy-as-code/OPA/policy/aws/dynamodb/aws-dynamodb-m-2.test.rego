package aws.dynamodb.m2

test_valid_vpc_endpoints {
	result = deny with input as data.mock.valid    
	count(result) == 0
}
test_invalid_no_vpc_endpoint {
	result = deny with input as data.mock.invalid.invalid_no_vpc_endpoint 
    result == {"AWS-DynamoDB-M-2: Resource '[\"aws_dynamodb_table.basic-dynamodb-table\"]' is used and traffic should be restricted to DynamoDB VPC endpoint (create DynamoDB VPC endpoints)"}
}
test_invalid_no_vpc_endpoint_policy {
	result = deny with input as data.mock.invalid.invalid_no_vpc_endpoint_policy    
	result == {"AWS-DynamoDB-M-2: VPC Endpoint 'aws_vpc_endpoint.dynamodb' has no policy (you must attach a policy and list resources)"}
}
test_invalid_vpc_endpoint_policy_wildcard {
	result = deny with input as data.mock.invalid.invalid_vpc_endpoint_policy_wildcard     
	result == {"AWS-DynamoDB-M-2: VPC Endpoint 'aws_vpc_endpoint.dynamodb' policy resources should be listed (specify in the policy what DynamoDB resources are accesible)"}}
