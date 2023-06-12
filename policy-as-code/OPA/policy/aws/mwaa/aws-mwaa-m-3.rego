package aws.mwaa.m3

# Ensure VPC endpoint exists for MWAA to prevent traffic leaving from AWS network

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-vpe-create-access.html#vpc-vpe-create-view-endpoints-examples

# Modify your MWAA Endpoint service related to your region (eu-central-1 is used in this example)
mwaa_endpoints_list = [
    "com.amazonaws.eu-central-1.s3",
    "com.amazonaws.eu-central-1.monitoring",
    "com.amazonaws.eu-central-1.ecr.dkr",
    "com.amazonaws.eu-central-1.ecr.api",
    "com.amazonaws.eu-central-1.logs",
    "com.amazonaws.eu-central-1.sqs",
    "com.amazonaws.eu-central-1.kms",
    "com.amazonaws.eu-central-1.airflow.api",
    "com.amazonaws.eu-central-1.airflow.env",
    "com.amazonaws.eu-central-1.airflow.ops"
]

is_service_endpoint_exists(resource, endpoints_list) = no_endpoint_list{
    no_endpoint_list := [endpoint |
        endpoint := endpoints_list[_]
        not data.aws.utils.is_service_vpc_endpoint_exists(resource, endpoint)
    ]
}

deny[reason]{
    service = data.utils.find_service_resource(input, "aws_mwaa")
    count(service) > 0

    no_endpoint_list := is_service_endpoint_exists(input, mwaa_endpoints_list)
    count(no_endpoint_list) > 0
    reason := sprintf("AWS-MWAA-M-3: Resource '%s' is used and traffic should be restricted to MWAA from VPC endpoint using servicenames '%s' (create MWAA related services VPC endpoints).", [service[0], no_endpoint_list])
}
