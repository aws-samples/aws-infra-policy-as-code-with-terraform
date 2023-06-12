package aws.ecr.m3

test_ecr_repo_compliant {
    result = deny with input as data.mock.ecr_repo_compliant
    count(result) == 0
}

test_ecr_repo_defaults {
    result = deny with input as data.mock.ecr_repo_defaults
    result == {"AWS-ECR-M-3: ECR central repository should have 'scan_on_push' enabled for 'aws_ecr_repository.ecr_repo_defaults'."}
}

test_ecr_repo_mutable {
    result = deny with input as data.mock.ecr_mutable
    result == {"AWS-ECR-M-3: ECR central repository should have 'scan_on_push' enabled for 'aws_ecr_repository.ecr_repo_mutable'."}
}

test_ecr_repo_no_scan{
     result = deny with input as data.mock.ecr_repo_no_scan
     result == {"AWS-ECR-M-3: ECR central repository should have 'scan_on_push' enabled for 'aws_ecr_repository.ecr_repo_no_scan'."}
}
