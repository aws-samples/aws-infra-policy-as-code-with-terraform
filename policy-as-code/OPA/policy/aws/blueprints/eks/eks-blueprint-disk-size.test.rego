package aws.blueprints.eks.disk_size

msg := {"'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster Node group should contain disk_size parameter"}

test_valid {
  result = deny with input as data.mock.disk_size_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.disk_size_invalid
  msg == result
}