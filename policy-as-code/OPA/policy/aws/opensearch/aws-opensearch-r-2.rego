package aws.opensearch.r2

# Encrypt the traffic on OpenSearch domain by enabling https/tls

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#domain_endpoint_options

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/data-protection.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_opensearch_domain"
}

is_https_enabled(resource) {
	resource.change.after.domain_endpoint_options[_].enforce_https == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_https_enabled(resource)
	reason := sprintf("AWS-OpenSearch-R-2: OpenSearch resource '%s' domain endpoint option enforce_https should not be set to false", [resource.address])
}
