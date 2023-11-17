package aws.blueprints.eks.selfManagedSecurityGroup

import future.keywords.in

# Check if self managed cluster nodes have security groups defined.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template#vpc_security_group_ids

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_launch_template"
}

is_security_group_enabled(resource) {
	count(resource.change.after.vpc_security_group_ids) > 0
} else {
	resource.change.after_unknown.vpc_security_group_ids == true
} else := false

deny[reason] {
	some resource in input.resource_changes
	is_in_scope(resource)
	not is_security_group_enabled(resource)
	reason := sprintf("'%s' EKS Cluster Managed Nodes Should have security groups defined", [resource.address])
}
