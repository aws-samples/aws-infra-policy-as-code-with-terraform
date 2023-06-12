package aws.opensearch.r1

# Enable advanced security options on Opensearch service for fine-grained controls

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#advanced_security_options

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_opensearch_domain"
}

is_fine_grained_access_enabled(resource) {
	resource.change.after.advanced_security_options[_].enabled==true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)

	not is_fine_grained_access_enabled(resource)
	reason := sprintf("AWS-OpenSearch-R-1: OpenSearch resource '%s' must be enabled with advanced_security_options", [resource.address])
}
