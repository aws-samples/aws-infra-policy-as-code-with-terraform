package aws.msk.m1

# Ensure data gathered and accessed by AWS MSK cluster is over TLS protected channel

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_msk_cluster"
}

is_tls_enabled_in_transit(resource){
	cluster := resource.change.after.encryption_info[_]
	[path,val] := walk(cluster.encryption_in_transit)
	protocol := val["client_broker"]
	protocol == "TLS"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
		
	not is_tls_enabled_in_transit(resource)
	message := "AWS-MSK-M-1: Protocol should be set to TLS for encryption_in_transit.client_broker for resource '%s'"
	reason := sprintf(message, [resource.address])
}
