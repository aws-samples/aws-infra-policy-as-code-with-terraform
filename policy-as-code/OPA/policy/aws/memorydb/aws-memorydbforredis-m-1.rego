package aws.memorydbforredis.m1

# Encryption in transit

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/memorydb_cluster#tls_enabled

# AWS link to policy defitinion/explanation
# https://docs.aws.amazon.com/memorydb/latest/devguide/security.html
 
is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_memorydb_cluster"
}

is_tls_enabled(resource) { 
	resource.change.after.tls_enabled == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_tls_enabled(resource)
	message := "AWS-MEMORYDB-FOR-REDIS-M-1:TLS must be enabled while creating MemoryDB Cluster '%s'"
	reason := sprintf(message, [resource.address])
}
