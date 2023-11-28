package aws.blueprints.eks.privateEndpoint

import future.keywords.in

# Check if cluster uses private endpoints.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_private_access

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html

is_in_scope(resource) {
  resource.mode == "managed"
  data.utils.is_create_or_update(resource.change.actions)
  resource.type == "aws_eks_cluster"
}

are_endpoints_private(resource) {
  resource.change.after.vpc_config[0].endpoint_private_access == true
  resource.change.after.vpc_config[0].endpoint_public_access == false
}

deny[reason] {
  some resource in input.resource_changes
  is_in_scope(resource)
  not are_endpoints_private(resource)
  reason := sprintf("'%s' EKS Cluster should only have private endpoints", [resource.address])
}
