package aws.mwaa.m5

# Ensure MWAA environment webserver Access mode has to be Private

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mwaa_environment#webserver_access_mode

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-webserveraccessmode


is_in_scope(resource) {
	resource.mode == "managed"
	resource.type == "aws_mwaa_environment"
	data.utils.is_create_or_update(resource.change.actions)
}

is_access_mode_private(resource){
    not resource.change.after.webserver_access_mode == "PUBLIC_ONLY"
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)
    not is_access_mode_private(resource)
    reason := sprintf("AWS-MWAA-M-5: MWAA environment '%s' webserver Access mode has to be Private (make sure 'webserver_access_mode' argument is set).", [resource.address])
}
