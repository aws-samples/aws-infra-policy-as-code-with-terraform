package aws.eks.r2

# Check if cluster node groups have disk_size parameter configured.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_node_group#disk_size

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html

is_in_scope(resource) {
  resource.mode == "managed"
  data.utils.is_create_or_update(resource.change.actions)
  resource.type == "aws_eks_node_group"
}

is_disk_size_present(resource){
  resource.change.after.disk_size
}

deny[reason] {
  resource := input.resource_changes[_]
  is_in_scope(resource)
  not is_disk_size_present(resource)
  reason := sprintf("AWS-EKS-R-2: '%s' EKS Cluster Node group should contain disk_size parameter", [resource.address])
}
