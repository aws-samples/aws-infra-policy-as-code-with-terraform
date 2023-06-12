package aws.apigateway.r1

# Enforcement of authorization for API Gateway Method

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage

# AWS link to policy defitinion/explanation
# https://aws.amazon.com/api-gateway/

blocked_method := ["NONE","COGNITO_USER_POOLS"]

deny[reason]{
    resource := input.resource_changes[_]
    resource.type == "aws_api_gateway_method"
    auth := resource.change.after.authorization
    auth == blocked_method[_]
    message := "AWS-API-GATEWAY-R-1: AWS_IAM or CUSTOM Authorization should be set for resource '%s'"
    reason := sprintf(message, [resource.address])
}
