package aws.eks.m3

msg := {"AWS-EKS-M-3: 'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster Should have cluster security group defined"}

test_valid {
  result = deny with input as data.mock.m3_valid
  count(result) == 0
}

test_noid_valid {
  result = deny with input as data.mock.m3_noid_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.m3_invalid
  msg == result
}
