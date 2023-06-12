package aws.eks.r1

msg := {"AWS-EKS-R-1: 'module.eks.aws_launch_template.this' EKS Cluster Managed Nodes Should have security groups defined"}

test_ref_valid {
  result = deny with input as data.mock.r1_ref_valid
  count(result) == 0
}

test_sgid_valid {
  result = deny with input as data.mock.r1_sgid_valid
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.r1_invalid
  msg == result
}
