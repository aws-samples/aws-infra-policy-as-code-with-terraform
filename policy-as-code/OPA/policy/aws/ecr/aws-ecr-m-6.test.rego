package aws.ecr.m6

test_ecr_vpc_endpoint_with_valid_aws_condition {
    result = deny with input as data.mock.ecr_vpc_endpoint_with_valid_aws_condition
    count(result) == 0
}

test_ecr_vpc_endpoint_with_valid_ecr_condition {
    result = deny with input as data.mock.ecr_vpc_endpoint_with_valid_ecr_condition
    count(result) == 0
}

test_ecr_vpc_endpoint_with_policy_no_condition {
    result = deny with input as data.mock.ecr_vpc_endpoint_with_policy_no_condition
    result = {"AWS-ECR-M-6: ECR vpc endpoint policy does not contain condition 'ecr:ResourceTag/ArtifactoryScanCompleted' for 'aws_vpc_endpoint.ecr_vpc_endpoint_with_policy_no_condition'."}
}

test_ecr_vpc_endpoint_with_no_policy {
    result = deny with input as data.mock.ecr_vpc_endpoint_with_no_policy
    result = {"AWS-ECR-M-6: ECR vpc endpoint policy is not defined for 'aws_vpc_endpoint.ecr_vpc_endpoint_with_no_policy'."}
}

test_ecr_vpc_endpoint_with_invalid_condition {
    result = deny with input as data.mock.ecr_vpc_endpoint_with_invalid_condition
    result = {"AWS-ECR-M-6: ECR vpc endpoint policy does not contain condition 'ecr:ResourceTag/ArtifactoryScanCompleted' for 'aws_vpc_endpoint.ecr_vpc_endpoint_with_invalid_condition'."}
}

test_ecr_vpc_policy_other_condition {
    result = deny with input as data.mock.ecr_vpc_policy_other_condition
    result = {"AWS-ECR-M-6: ECR vpc endpoint policy does not contain condition 'ecr:ResourceTag/ArtifactoryScanCompleted' for 'aws_vpc_endpoint.ecr_vpc_policy_other_condition'."}
}
