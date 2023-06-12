package aws.apigateway.m2

# Enforce encryption if caching is enabled in REST API

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage

# AWS link to policy defitinion/explanation
# https://aws.amazon.com/api-gateway/

contains_terraform_resource(array, value) {
	array[_].type = value
} 

is_cache_cluster_enabled(resource) {
    data.utils.is_create_or_update(resource.change.actions)
    resource.mode == "managed"
    resource.change.after.cache_cluster_enabled == true
}

is_cache_data_encrypted(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
    method_settings := resource.change.after.settings[_]
    method_settings.cache_data_encrypted == true
}

deny[reason] {
    resource := input.resource_changes[_]
	[path1, api_gw_stage] := walk(resource)
	api_gw_stage.type == "aws_api_gateway_stage"
	is_cache_cluster_enabled(api_gw_stage)
    not contains_terraform_resource(input.resource_changes,"aws_api_gateway_method_settings")
	message := "AWS-API-GATEWAY-M-2: If cache_cluster_enabled is set to true, then cache_data_encrypted must also be set to true. Set this parameter using aws_api_gateway_method_settings resource. '%s'"
    reason := sprintf(message, [api_gw_stage.address])
}

deny[reason] {
    resource := input.resource_changes[_]
	[path1, api_gw_stage] := walk(resource)
	api_gw_stage.type == "aws_api_gateway_stage"
	is_cache_cluster_enabled(api_gw_stage)
    [path2, api_gw_method_settings] := walk(input.resource_changes)
    contains_terraform_resource(input.resource_changes,"aws_api_gateway_method_settings")
    api_gw_method_settings.type == "aws_api_gateway_method_settings"
    not is_cache_data_encrypted(api_gw_method_settings)
    message := "AWS-API-GATEWAY-M-2: If cache_cluster_enabled is set to true then cache_data_encrypted must also be set to true. '%s'"
    reason := sprintf(message, [api_gw_stage.address])
}

