package aws.dynamodb.m2

# This policy ensures that vpc endpoint with a well written policy exists before creating resources

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/secretsmanager/latest/userguide/vpc-endpoint-overview.html

# Modify your DynamoDB Endpoint service related to your region (eu-central-1 is used in this example)
DYNAMODB_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.dynamodb"

# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
    service = data.utils.find_service_resource(input, "aws_dynamodb_table")
    count(service) > 0
    not data.aws.utils.is_service_vpc_endpoint_exists(input, DYNAMODB_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-DynamoDB-M-2: Resource '%s' is used and traffic should be restricted to DynamoDB VPC endpoint (create DynamoDB VPC endpoints)", [service])
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_vpc_endpoint"
	data.utils.is_resource_create_or_update(resource)
    resource.change.after.service_name == DYNAMODB_ENDPOINT_SERVICE_NAME
    not resource.change.after.policy
	reason := sprintf("AWS-DynamoDB-M-2: VPC Endpoint '%s' has no policy (you must attach a policy and list resources)", [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_vpc_endpoint"
	data.utils.is_resource_create_or_update(resource)
    resource.change.after.service_name == DYNAMODB_ENDPOINT_SERVICE_NAME
    policyString := resource.change.after.policy
    policy := json.unmarshal(policyString)
    statement := policy.Statement[_]
    statement.Resource == "*"
	reason := sprintf("AWS-DynamoDB-M-2: VPC Endpoint '%s' policy resources should be listed (specify in the policy what DynamoDB resources are accesible)", [resource.address])
}