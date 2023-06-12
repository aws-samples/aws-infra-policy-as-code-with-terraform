package aws.systemsmanager.m1

# Ensure Parameter store “Secure String” parameter is encrypted with AWS CMK.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter#key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/kms/latest/developerguide/services-parameter-store.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_ssm_parameter"
}

is_customer_cmk_encrypted(resource) {
	not is_null(resource.change.after.key_id)
	not resource.change.after.key_id == ""
	startswith(resource.change.after.key_id,"arn:aws:kms:")
} else {
	config_resource := data.utils.find_configuration_resource(input, resource)
	references := config_resource.expressions.key_id.references[_]
	contains(references,"aws_kms_key.")
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	resource.change.after.type == "SecureString"
	not is_customer_cmk_encrypted(resource)
	message := "AWS-SYSTEMSMANAGER-M-1: Parameter store security string parameter '%s' should be configured with CMK."
	reason := sprintf(message, [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not resource.change.after.type == "SecureString"
	message := "AWS-SYSTEMSMANAGER-M-1: Only SecureString parameter type is allowed for Parameter store '%s'."
	reason := sprintf(message, [resource.address])
}
