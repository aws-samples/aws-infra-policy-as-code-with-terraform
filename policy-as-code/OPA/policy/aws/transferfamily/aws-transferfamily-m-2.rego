package aws.transferfamily.m2

# AWS Transfer Family: SSH keys should not be used for authentication

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/transfer_server#identity_provider_type

# AWS link to policy definition/explanation
# https://aws.amazon.com/aws-transfer-family/?nc=sn&loc=0

allowed_identity_provider := ["API_GATEWAY", "AWS_LAMBDA", "AWS_DIRECTORY_SERVICE"]

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_transfer_server"
}

is_valid_provider_selected(resource) {
	data.utils.contains_element(allowed_identity_provider, resource.change.after.identity_provider_type)
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_valid_provider_selected(resource)
	message := "AWS-TRANSFER_FAMILY-M-2:TRANSFER_FAMILY Identity Provider should be selected as API Gateway, AWS LAMBDA or AWS DIRECTORY SERVICE '%s'"
	reason := sprintf(message, [resource.address])
}
