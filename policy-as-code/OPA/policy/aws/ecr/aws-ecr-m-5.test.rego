package aws.ecr.m5

test_valid_lifecycle_policy_1 {
    result = deny with input as data.mock.valid_lifecycle_policy
    count(result) == 0
}

test_valid_lifecycle_policy_2 {
    result = deny with input as data.mock.valid_lifecycle_policy2
    count(result) == 0
}

test_valid_lifecycle_policy_3 {
    result = deny with input as data.mock.valid_lifecycle_policy3
    count(result) == 0
}

test_invalid_lifecycle_policy {
    result1 = deny with input as data.mock.invalid_lifecycle_policy
    result1 == {"AWS-ECR-M-5: ECR image lifecycle policy of deleting untagged images or deleting olderthan 2 tagged images is not defined for 'aws_ecr_lifecycle_policy.foopolicy'."}
}

test_invalid_lifecycle_policy2 {
    result1 = deny with input as data.mock.invalid_lifecycle_policy2
    result1 == {"AWS-ECR-M-5: ECR image lifecycle policy of deleting untagged images or deleting olderthan 2 tagged images is not defined for 'aws_ecr_lifecycle_policy.foopolicy'."}
}

test_missing_lifecycle_policy{
     result1 = deny with input as data.mock.missing_lifecycle_policy
     result1 == {"AWS-ECR-M-5: ECR image lifecycle policy is not defined for 'aws_ecr_lifecycle_policy.foopolicy'."}
}

test_no_lifecycle_policy_resource{
     result1 = deny with input as data.mock.no_lifecycle_policy_resource
     result1 == {"AWS-ECR-M-5: ECR repository 'aws_ecr_repository.foo' does not have image lifecycle policy rules defined."}
}

test_multiple_repos_no_lifecycle_policy{
    result1 = deny with input as data.mock.multiple_repos_no_lifecycle
    result1 == {"AWS-ECR-M-5: ECR repository 'aws_ecr_repository.test' does not have image lifecycle policy rules defined."}
}

test_valid_no_op_ecr_repo_no_lifecycle_policy {
    result = deny with input as data.mock.no_op_ecr_repo_no_lifecycle_policy
    result == {"AWS-ECR-M-5: ECR repository 'aws_ecr_repository.foo' does not have image lifecycle policy rules defined."}
}

test_valid_no_op_ecr_repo_lifecycle_policy {
    result = deny with input as data.mock.no_op_ecr_repo_lifecycle_policy
    count(result) == 0
}
