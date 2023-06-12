package aws.transferfamily.m1

# Ensure neither FTP nor any plain-text protocol should be used for data transfer

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/transfer_server#protocols

# AWS link to policy definition/explanation
# https://aws.amazon.com/aws-transfer-family/?nc=sn&loc=0
 
not_allowed_protocol := ["FTP","AS2"]


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_transfer_server"
}

is_ftp_selected(resource) {
	some protocol 
	resource.change.after.protocols[_] == not_allowed_protocol[protocol]
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	is_ftp_selected(resource)
	message := "AWS-TRANSFER_FAMILY-M-1:TRANSFER_FAMILY protocol should be set to FTPS/SFTP '%s'"
	reason := sprintf(message, [resource.address])
}
