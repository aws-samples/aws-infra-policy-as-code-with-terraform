package aws.blueprints.eks.privateEndpoint

msg := {"'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster should only have private endpoints"}

test_valid {
  result = deny with input as data.mock.pe_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.pe_invalid
  msg == result
}