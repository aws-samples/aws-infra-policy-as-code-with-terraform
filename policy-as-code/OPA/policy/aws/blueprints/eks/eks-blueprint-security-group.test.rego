package aws.blueprints.eks.securityGroup

msg := {"'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster Should have cluster security group defined"}

test_valid {
  result = deny with input as data.mock.sg_valid
  count(result) == 0
}

test_noid_valid {
  result = deny with input as data.mock.sg_noid_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.sg_invalid
  msg == result
}