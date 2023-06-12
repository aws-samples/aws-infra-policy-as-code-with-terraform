package aws.datasync.m2

test_valid_datasync_vpc_endpoints {
    result = deny with input as data.mock.valid_datasync_vpc_endpoint
    count(result) == 0
}

test_invalid_vpc_endpoint{
    result = deny with input as data.mock.other_service_vpc_endpoint
    msg = {"AWS-DATASYNC-M-2: Resource 'aws_datasync_agent.example' is used and traffic should be restricted to DataSync from VPC endpoint using servicename 'com.amazonaws.eu-central-1.datasync' (create datasync VPC endpoint)"}
    result == msg
}
