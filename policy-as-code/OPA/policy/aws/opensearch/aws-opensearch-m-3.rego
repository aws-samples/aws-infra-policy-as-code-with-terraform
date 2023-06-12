package aws.opensearch.m3

# Enable node to node encryption for OpenSearch services

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#node_to_node_encryption 

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html 

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_opensearch_domain"
}

is_node_to_node_encryption_enabled(resource) {
	resource.change.after.node_to_node_encryption[_].enabled == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_node_to_node_encryption_enabled(resource)
	reason := sprintf("AWS-OpenSearch-M-3: OpenSearch resource '%s' must use node to node encryption", [resource.address])
}
