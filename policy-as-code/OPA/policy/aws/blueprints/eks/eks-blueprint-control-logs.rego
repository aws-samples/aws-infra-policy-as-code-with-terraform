package aws.blueprints.eks.controllogs

import future.keywords.in

# Check if the EKS cluster has valid control plane logs enabled.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html

valid_logs := {"api", "audit", "authenticator"}

is_in_scope(resource) {
  resource.mode == "managed"
  data.utils.is_create_or_update(resource.change.actions)
  resource.type == "aws_eks_cluster"
}

is_logging_valid(resource) {
	cluster_logs := {lt | some lt in resource.change.after.enabled_cluster_log_types}
	required_logs := valid_logs - cluster_logs
	count(required_logs) == 0
}

deny[reason] {
	some resource in input.resource_changes
	is_in_scope(resource)
	not is_logging_valid(resource)
    reason := sprintf("'%s' EKS Cluster should contain following cluster log types enabled - 'api', 'audit', 'authenticator'", [resource.address])
}
