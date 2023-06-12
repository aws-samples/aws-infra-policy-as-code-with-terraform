package aws.memorydbforredis.m2

# Encryption at rest

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/memorydb_cluster#kms_key_arn

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

is_kms_key_set(resource) {
    keyArn := resource.change.after.kms_key_arn
    not is_null(keyArn)
	not keyArn == ""
    startswith(keyArn, "arn:aws:kms:")
} else {
    resource.change.after_unknown.kms_key_arn == true
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource, supported_resource_types)
	not is_kms_key_set(resource)
	message := "AWS-MEMORYDB-FOR-REDIS-M-2:Server side encryption must be enabled by using customer managed key '%s'"
	reason := sprintf(message, [resource.address])
}
