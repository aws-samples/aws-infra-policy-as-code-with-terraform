package aws.eks.r2

msg := {"AWS-EKS-R-2: 'module.eks.aws_eks_node_group.eks_nodes' EKS Cluster Node group should contain disk_size parameter"}

test_valid {
  result = deny with input as data.mock.r2_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.r2_invalid
  msg == result
}
