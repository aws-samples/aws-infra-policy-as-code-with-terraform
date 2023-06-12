package aws.memorydbforredis.m3

# Default ACL should not be used

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/memorydb_cluster#acl_name

# AWS link to policy defitinion/explanation
# https://docs.aws.amazon.com/memorydb/latest/devguide/security.html

supported_resource_types = ["aws_memorydb_cluster"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_default_acl_selected(resource){
	resource.change.after.acl_name == "open-access"
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource, supported_resource_types)
	is_default_acl_selected(resource)
	message := "AWS-MEMORYDB-FOR-REDIS-M-3: For user Authentication default ACL should not be accepted, Create custom ACL by using aws_memorydb_acl '%s'"
	reason := sprintf(message, [resource.address])
}
