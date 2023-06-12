package aws.ecr.m4

# VPC endpoint to prevent ECR network traffic leaving from the AWS network
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# Ensure that ECR should have VPC endpoint to prevent network traffic leaving from the AWS network.
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html#ecr-setting-up-vpc-create

# Modify your ECR Endpoint service related to your region (eu-central-1 is used in this example)
ECR_API_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.ecr.api"
ECR_DKR_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.ecr.dkr"


deny[reason]{
    service = data.utils.find_service_resource(input, "aws_ecr")
    count(service) > 0
    not data.aws.utils.is_service_vpc_endpoint_exists(input, ECR_DKR_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-ECR-M-4: Resource '%s' is used and traffic should be restricted to ECR from VPC endpoint using servicename '%s' (create ecr VPC endpoint)", [service[0], ECR_DKR_ENDPOINT_SERVICE_NAME])
}

deny[reason]{
    service = data.utils.find_service_resource(input, "aws_ecr")
    count(service) > 0
    not data.aws.utils.is_service_vpc_endpoint_exists(input,  ECR_API_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-ECR-M-4: Resource '%s' is used and traffic should be restricted to ECR from VPC endpoint using servicename '%s' (create ecr VPC endpoint)", [service[0], ECR_API_ENDPOINT_SERVICE_NAME])
}
