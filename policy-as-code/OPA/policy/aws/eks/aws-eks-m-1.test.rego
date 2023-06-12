package aws.eks.m1

msg := {"AWS-EKS-M-1: 'module.eks.aws_eks_cluster.eks_cluster' EKS Cluster should countain following cluster log types enabled - 'api', 'audit', 'authenticator', 'controllerManager', 'scheduler'"}

test_valid {
  result = deny with input as data.mock.m1_valid
  count(result) == 0
}

test_invalid_api {
  result = deny with input as data.mock.m1_api_invalid
  msg == result
}

test_invalid_audit {
  result = deny with input as data.mock.m1_audit_invalid
  msg == result
}

test_invalid_authenticator {
  result = deny with input as data.mock.m1_authenticator_invalid
  msg == result
}

test_invalid_controllerManager {
  result = deny with input as data.mock.m1_controllerManager_invalid
  msg == result
}

test_invalid_scheduler {
  result = deny with input as data.mock.m1_scheduler_invalid
  msg == result
}
