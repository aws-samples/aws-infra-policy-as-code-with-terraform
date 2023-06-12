package aws.eks.m2

# Check if cluster uses private endpoints.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#endpoint_private_access

# AWS link to policy defitinio/explanation
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
  resource := input.resource_changes[_]
  is_in_scope(resource)
  not are_endpoints_private(resource)
  reason := sprintf("AWS-EKS-M-2: '%s' EKS Cluster should have only private endpoints", [resource.address])
}
