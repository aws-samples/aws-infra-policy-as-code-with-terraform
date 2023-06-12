package aws.apigateway.m1

# API Gateway resources should not be publicly accessible

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api

# AWS link to policy defitinion/explanation
# https://aws.amazon.com/api-gateway/

allowed_endpoint_configuration_types := "PRIVATE"

is_in_scope(resource) {
    resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
    resource.type == "aws_api_gateway_rest_api"
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)
    endpoint_configuration := resource.change.after.endpoint_configuration[_]
    not data.utils.contains_element(endpoint_configuration.types, allowed_endpoint_configuration_types)
    message := "AWS-API-GATEWAY-M-1: API Gateway resources should not be publicly accessible. Choose endpoint_configuration_types as PRIVATE '%s'"
    reason := sprintf(message, [resource.address])
}