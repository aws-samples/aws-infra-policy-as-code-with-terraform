package aws.blueprints.eks.controllogs

msg := {"'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster should contain following cluster log types enabled - 'api', 'audit', 'authenticator'"}

test_valid {
  result = deny with input as data.controllogs_valid
  count(result) == 0
}

test_invalid_api {
  result = deny with input as data.controllogs_api_invalid
  msg == result
}