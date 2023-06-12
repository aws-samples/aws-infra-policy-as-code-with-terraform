package aws.apigateway.m4

# Restrict API deployment if logging is not enabled

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage

# AWS link to policy defitinion/explanation
# https://aws.amazon.com/api-gateway/

not_allowed_logging_level := "OFF"

contains_terraform_resource(array, value) {
	array[_].type == value
} 

is_logging_level_present(settings){
    logging_level := settings.logging_level
}

is_logging_level_allowed(value) {
	value != not_allowed_logging_level
} 

is_in_scope(resource, type) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_api_gateway_stage")
    not contains_terraform_resource(input.resource_changes,"aws_api_gateway_method_settings")
    message := "AWS-API-GATEWAY-M-4: If aws_api_gateway_stage is created then aws_api_gateway_method_settings must be used with logging_level set to either INFO or ERROR '%s'"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_api_gateway_method_settings")
    settings := resource.change.after.settings[_]
    is_logging_level_present(settings)
    logging_level := settings.logging_level
    not is_logging_level_allowed(logging_level)
    message := "AWS-API-GATEWAY-M-4: logging_level under aws_api_gateway_method_settings should not be OFF '%s'"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_api_gateway_method_settings")
    settings := resource.change.after.settings[_]
    not is_logging_level_present(settings)
    message := "AWS-API-GATEWAY-M-4:logging_level is not defined in aws_api_gateway_method_settings. Set logging_level as INFO or ERROR '%s'"
    reason := sprintf(message, [resource.address])
}
