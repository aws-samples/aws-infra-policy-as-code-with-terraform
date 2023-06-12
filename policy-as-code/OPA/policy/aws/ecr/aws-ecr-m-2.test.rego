package aws.ecr.m2

test_ecr_repo_policy_compliant {
    result = deny with input as data.mock.ecr_repo_policy_compliant
    count(result) == 0
}

test_ecr_repo_policy_aws_compliant {
    result = deny with input as data.mock.valid_aws_permission_policy
    count(result) == 0
}

test_ecr_repo_policy_service_compliant {
    result = deny with input as data.mock.valid_service_permission_policy
    count(result) == 0
}

test_ecr_repo_policy_noncompliant{
    result = deny with input as data.mock.excess_permission_policy
    result == {"AWS-ECR-M-2: ECR central repository resource policy should use least privilege permissions for 'aws_ecr_repository_policy.repopolicy'."}
}

test_ecr_repo_policy_aws_excess_permission_noncompliant{
    result = deny with input as data.mock.excess_aws_permission_policy
    result == {"AWS-ECR-M-2: ECR central repository resource policy should use least privilege permissions for 'aws_ecr_repository_policy.repopolicy'."}
}

test_ecr_repo_policy_aws_excess_permission_noncompliant{
    result = deny with input as data.mock.excess_service_permission_policy
    result == {"AWS-ECR-M-2: ECR central repository resource policy should use least privilege permissions for 'aws_ecr_repository_policy.repopolicy'."}
}