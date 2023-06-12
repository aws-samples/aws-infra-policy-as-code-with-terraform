package aws.lambda.m1

# Restrict traffic to functions within own AWS account

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc-endpoints.html#vpc-endpoint-policy

# Modify your Lambda Endpoint service related to your region (eu-central-1 is used in this example)
LAMBDA_ENDPOINT := "com.amazonaws.eu-central-1.lambda"

# ----------------------------------------------------------------------------------------------
# Functions block
# ----------------------------------------------------------------------------------------------

policy_has_account_condition_key(statement) {
    statement.Effect == "Allow"
    statement.Condition.StringEquals["aws:PrincipalAccount"]
} else {
    statement.Effect == "Deny"
    statement.Condition.StringNotEquals["aws:PrincipalAccount"]
} else = false {
	true
}

# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_vpc_endpoint"
	data.utils.is_resource_create_or_update(resource)
    resource.change.after.service_name == LAMBDA_ENDPOINT

    not resource.change.after.policy
	reason := sprintf("AWS-Lambda-M-1: VPC Endpoint '%s' has no policy (you must attach a policy and restrict access to the same account)", [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_vpc_endpoint"
	data.utils.is_resource_create_or_update(resource)
    resource.change.after.service_name == LAMBDA_ENDPOINT

    policyString := resource.change.after.policy
    policy := json.unmarshal(policyString)
    statement := policy.Statement[_]
    not policy_has_account_condition_key(statement)
	reason := sprintf("AWS-Lambda-M-1: VPC Endpoint '%s' policy should restrict traffic to functions within own AWS account (use 'aws:PrincipalAccount' condition key)", [resource.address])
}