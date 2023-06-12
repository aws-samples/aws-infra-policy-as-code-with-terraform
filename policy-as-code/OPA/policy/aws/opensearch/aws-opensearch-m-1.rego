package aws.opensearch.m1

# OpenSearch cluster should be enabled with Customer Managed Key(CMK) and configure dedicated key for OpenSearch

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#encrypt_at_rest

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html

is_kms_key_in_scope(resource) {
	resource.mode == "managed"
	change_actions = resource.change.actions
	change_actions[count(change_actions) - 1] == ["create", "update","no-op"][_]
	resource.type == "aws_kms_key"
}

is_in_scope(resource,type) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

is_kms_key_set(kms_key_id) {
	not is_null(kms_key_id)
	not kms_key_id == ""
}

is_valid_key(resource,kms_key_id) {
	resource.change.after.key_id  == kms_key_id 
} else {
	resource.change.after.arn == kms_key_id 
}

extract_kms_key(kms_key_id) {
	some key
	is_kms_key_in_scope(input.resource_changes[key])
	is_valid_key(input.resource_changes[key],kms_key_id)
}

extract_kms_key_from_reference(kms_reference) {
	some key
	is_kms_key_in_scope(input.resource_changes[key]) 
	data.utils.contains_element(kms_reference,input.resource_changes[key].address)
}

is_valid_key_defined(resource) {
	kms_key_id := trim_space(resource.change.after.encrypt_at_rest[_].kms_key_id)
	is_kms_key_set(kms_key_id)
	extract_kms_key(kms_key_id)

} else {
	config_resource := data.utils.find_configuration_resource(input, resource)
	references := config_resource.expressions.encrypt_at_rest[_].kms_key_id.references
	extract_kms_key_from_reference(references)
}

is_encryption_enabled(resource) {
	resource.change.after.encrypt_at_rest[_].enabled == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource,"aws_opensearch_domain")

	not is_encryption_enabled(resource)
	reason := sprintf("AWS-OpenSearch-M-1: OpenSearch resource '%s' must be configured with encrypt_at_rest as true", [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource,"aws_opensearch_domain")
 	
	not is_valid_key_defined(resource)
 	reason := sprintf("AWS-OpenSearch-M-3: OpenSearch resource '%s' must set to use CMK KMS key for encryption at rest using kms_key_id", [resource.address])
}	

