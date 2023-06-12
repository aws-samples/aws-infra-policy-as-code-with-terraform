package aws.apigateway.m3

# For HTTP backend integrations, the URL endpoint should be HTTPS URL

# AWS-API-GW-M3-WITH-BODY OPA policy to restriction use of http urls in integration when provided in 'body' argument of 'aws_api_gateway_rest_api' resource

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_integration#type

# AWS link to policy defitinion/explanation
# https://aws.amazon.com/api-gateway/?nc2=type_a

not_allowed_uri_protocol := "http://"

is_in_scope(resource, type) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

is_not_valid_uri(uri) {
	regex.match(not_allowed_uri_protocol, uri)
} 

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_api_gateway_integration")
    resource.change.after.type == "HTTP"
    uri_output :=  resource.change.after.uri
    is_not_valid_uri(uri_output)
    message := "aws-apigw-m-3: Protocol provided in URL for HTTP backend integration should be set to https '%s'"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_api_gateway_rest_api")
    body := json.unmarshal(resource.change.after.body)
    paths := body.paths
    [_, value] := walk(paths)
    uri_output := value.uri
    is_not_valid_uri(uri_output)
    message := "aws-apigw-m-3: Protocol provided in URL in body json for HTTP backend should be set to https '%s'"
    reason := sprintf(message, [resource.address])
}

