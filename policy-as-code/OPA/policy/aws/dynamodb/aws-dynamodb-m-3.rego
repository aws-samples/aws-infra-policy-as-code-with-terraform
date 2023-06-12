package aws.dynamodb.m3

# Ensures enablement of both encryption in transit and at rest when creating your DAX cluster.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXDataProtection.html

# ----------------------------------------------------------------------------------------------
# Functions block
# ----------------------------------------------------------------------------------------------
tls_exists(resource) { 
	resource.change.after.cluster_endpoint_encryption_type == "TLS"
}
cmk_exists(resource) { 
	resource.change.after.server_side_encryption[_].enabled == true
}
# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_dax_cluster"
	data.utils.is_resource_create_or_update(resource)
	not tls_exists(resource)
    reason := sprintf("AWS-DynamoDB-M-3: Resource '%s' cluster_endpoint_encryption_type must be set to TLS", [resource.address])
}
deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_dax_cluster"
	data.utils.is_resource_create_or_update(resource)
	not cmk_exists(resource)
    reason := sprintf("AWS-DynamoDB-M-3: Resource '%s' Server Side Encryption must be enabled", [resource.address])
}