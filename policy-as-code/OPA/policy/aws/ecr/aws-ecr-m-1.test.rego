package aws.ecr.m1

test_ecr_repo_immutable {
    result = deny with input as data.mock.ecr_repo_immutable
    count(result) == 0
}

test_ecr_repo_mutable {
    result = deny with input as data.mock.ecr_repo_mutable
    result == {"AWS-ECR-M-1: ECR central repository should have 'image_tag_mutability' set to 'IMMUTABLE' for 'aws_ecr_repository.ecr_repo_mutable'."}
}

