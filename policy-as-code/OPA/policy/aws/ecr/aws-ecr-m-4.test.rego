package aws.ecr.m4


test_valid_ecr_vpc_endpoints {
    result = deny with input as data.mock.valid_ecr_vpc_endpoints
    count(result) == 0
}

test_valid_ecr_with_no_api_endpoint{
    result = deny with input as data.mock.valid_ecr_with_no_api_endpoint
    msg = {"AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.api' (create ecr VPC endpoint)"}
    result == msg
}

test_valid_ecr_with_no_dkr_endpoint{
    result = deny with input as data.mock.valid_ecr_with_no_dkr_endpoint
    msg = {"AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.dkr' (create ecr VPC endpoint)"}
    result == msg
}

test_invalid_vpc_endpoint{
    result = deny with input as data.mock.ecr_invalid_vpc_endpoint
    msg = {
    "AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.api' (create ecr VPC endpoint)",
    "AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.dkr' (create ecr VPC endpoint)"}
    result == msg
}

test_invalid_vpc_endpoint{
    result = deny with input as data.mock.ecr_no_vpc_endpoint
    msg = {
    "AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.api' (create ecr VPC endpoint)",
    "AWS-ECR-M-4: Resource 'aws_ecr_repository.ecr_repo_compliant' is used and traffic should be restricted to ECR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.ecr.dkr' (create ecr VPC endpoint)"}
    result == msg
}

