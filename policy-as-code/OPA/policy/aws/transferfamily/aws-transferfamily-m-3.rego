package aws.transferfamily.m3

# Data gathered and accessed by the service is over TLS protected channel. All communication inside the cluster must be encrypted

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/transfer_server#security_policy_name

# AWS link to policy definition/explanation
# https://aws.amazon.com/aws-transfer-family/?nc=sn&loc=0

allowed_security_policy := ["TransferSecurityPolicy-2022-03","TransferSecurityPolicy-2020-06"]

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_transfer_server"
}

is_valid_security_policy_selected(resource) {
	data.utils.contains_element(allowed_security_policy, resource.change.after.security_policy_name)
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_valid_security_policy_selected(resource)
	message := "AWS-TRANSFER_FAMILY-M-3:TRANSFER_FAMILY Security Policy should be selected either TransferSecurityPolicy-2022-03 or TransferSecurityPolicy-2020-06 '%s'"
	reason := sprintf(message, [resource.address])
}
