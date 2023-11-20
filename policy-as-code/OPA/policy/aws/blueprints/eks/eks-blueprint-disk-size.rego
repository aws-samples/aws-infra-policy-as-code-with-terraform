package aws.blueprints.eks.disk_size


import future.keywords.in

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
  some resource in input.resource_changes
  is_in_scope(resource)
  not is_disk_size_present(resource)
  reason := sprintf("'%s' EKS Cluster Node group should contain disk_size parameter", [resource.address])
}