package aws.opensearch.m4

# Enable Audit and Error logs for OpenSearch service

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#log_publishing_options

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_opensearch_domain"
}

is_log_type_set(log_type) {
	not is_null(log_type)
	not log_type == ""
}

is_error_log_enabled(resource) {
	some log_config
	resource.change.after.log_publishing_options[log_config].enabled == true
	log_type := trim_space(resource.change.after.log_publishing_options[log_config].log_type)
	is_log_type_set(log_type)
	log_type == "ES_APPLICATION_LOGS"
}

is_audit_log_enabled(resource) {
	some log_config
	resource.change.after.log_publishing_options[log_config].enabled == true
	log_type := trim_space(resource.change.after.log_publishing_options[log_config].log_type)
	is_log_type_set(log_type)
	log_type == "AUDIT_LOGS"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_error_log_enabled(resource)
	reason := sprintf("AWS-OpenSearch-M-4: OpenSearch resource '%s' must have error logs(log_type ES_APPLICATION_LOGS) enabled", [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_audit_log_enabled(resource)
	reason := sprintf("AWS-OpenSearch-M-4: OpenSearch resource '%s' must have audit logs(log_type AUDIT_LOGS) enabled", [resource.address])
}
