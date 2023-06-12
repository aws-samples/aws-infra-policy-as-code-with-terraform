package aws.eks.m2

msg := {"AWS-EKS-M-2: 'module.midtier.aws_eks_cluster.eks_cluster' EKS Cluster should have only private endpoints"}

test_valid {
  result = deny with input as data.mock.valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.invalid
  msg == result
}
