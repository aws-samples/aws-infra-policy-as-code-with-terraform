package aws.transferfamily.m4

# AWS Transfer family server should NOT be publicly accessible over the internet

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/transfer_server#endpoint_type

# AWS link to policy definition/explanation
# https://aws.amazon.com/aws-transfer-family/?nc=sn&loc=0

allowed_endpoint_type := "VPC"


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_transfer_server"
}

is_allowed_endpoint_type_selected(resource) {
	resource.change.after.endpoint_type == allowed_endpoint_type
}

is_internetfacing_type_endpoint(resource){
	is_allowed_endpoint_type_selected(resource)
	endpoint_details := resource.change.after.endpoint_details[_]
	endpoint_details.address_allocation_ids == null 
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_internetfacing_type_endpoint(resource)
	message := "AWS-TRANSFER_FAMILY-M-4:TRANSFER_FAMILY Endpoint Type should be selected as VPC and Public IP must be blocked '%s'"
	reason := sprintf(message, [resource.address])
}



