package aws.eks.m1

# Check if cluster has valid logs enabled.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html

valid_logs := {"api", "audit", "authenticator", "controllerManager", "scheduler"}

is_in_scope(resource) {
  resource.mode == "managed"
  data.utils.is_create_or_update(resource.change.actions)
  resource.type == "aws_eks_cluster"
}

is_logging_valid(resource) {
  cluster_logs := { lt | lt := resource.change.after.enabled_cluster_log_types[_] }
  required_logs := valid_logs - cluster_logs
  count(required_logs) == 0
}

deny[reason] {
  resource := input.resource_changes[_]
  is_in_scope(resource)
  not is_logging_valid(resource)
  reason := sprintf("AWS-EKS-M-1: '%s' EKS Cluster should countain following cluster log types enabled - 'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'", [resource.address])
}
