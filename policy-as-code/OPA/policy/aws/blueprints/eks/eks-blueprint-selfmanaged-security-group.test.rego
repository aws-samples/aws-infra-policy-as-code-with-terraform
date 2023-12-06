package aws.blueprints.eks.selfManagedSecurityGroup

msg := {"'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster Managed Nodes Should have security groups defined"}

test_ref_valid {
  result = deny with input as data.mock.sm_sg_valid
  count(result) == 0
}

test_sgid_valid {
  result = deny with input as data.mock.sm_sgid_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.sm_sg_invalid
  msg == result
}