package aws.datasync.m2

# Ensure that DataSync should have VPC endpoint to prevent network traffic leaving from the AWS network.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# Configure VPC endpoint for DataSync
# https://docs.aws.amazon.com/datasync/latest/userguide/datasync-in-vpc.html
# https://docs.aws.amazon.com/datasync/latest/userguide/datasync-in-vpc.html#create-agent-steps-vpc

# Modify your Datasync endpoint related to your region (eu-central-1 is used in this example)
DATASYNC_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.datasync"

deny[reason]{
    service = data.utils.find_service_resource(input, "aws_datasync")
    count(service) > 0

    not data.aws.utils.is_service_vpc_endpoint_exists(input, DATASYNC_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-DATASYNC-M-2: Resource '%s' is used and traffic should be restricted to DataSync from VPC endpoint using servicename '%s' (create datasync VPC endpoint)", [service[0], DATASYNC_ENDPOINT_SERVICE_NAME])
}
