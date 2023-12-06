package aws.blueprints.eks.securityGroup

import future.keywords.in

# Check if cluster has security group defined.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#security_group_ids

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html

is_in_scope(resource) {
  resource.mode == "managed"
  data.utils.is_create_or_update(resource.change.actions)
  resource.type == "aws_eks_cluster"
}

is_security_group_enabled(resource){
  resource.change.after.vpc_config[0].security_group_ids
  count(resource.change.after.vpc_config[0].security_group_ids) > 0
} else {
  resource.change.after_unknown.vpc_config[0].security_group_ids == true
} else = false{
  true
}

deny[reason] {
  some resource in input.resource_changes
  is_in_scope(resource)
  not is_security_group_enabled(resource)
  reason := sprintf("'%s' EKS Cluster Should have cluster security group defined", [resource.address])
}
