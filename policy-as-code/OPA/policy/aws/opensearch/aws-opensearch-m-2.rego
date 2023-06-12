package aws.opensearch.m2

# OpenSearch services should be deployed in VPC

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#vpc_options

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_opensearch_domain"
}

is_vpc_subnets_specified(resource) {
	subnet_ids := resource.change.after.vpc_options[_].subnet_ids
	count(subnet_ids)>0
} else {
	resource.change.after_unknown.vpc_options[_].subnet_ids == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)

	not is_vpc_subnets_specified(resource)
	reason := sprintf("AWS-OpenSearch-M-2: OpenSearch resource '%s' must be deployed in VPC by setting vpc_options subnet_ids", [resource.address])
}

