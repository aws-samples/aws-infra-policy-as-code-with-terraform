package aws.dms.m4

test_dms_vpc_endpoint_with_valid_policy {
    result = deny with input as data.mock.valid
    print(result)
    count(result) == 0
}

test_dms_vpc_endpoint_with_invalid_policy {
    result = deny with input as data.mock.invalid
    result == {"AWS-DMS-M-4: DMS vpc endpoint policy does not contain condition 'aws:ResourceOrgID' for 'aws_vpc_endpoint.dms_vpc_endpoint_with_invalid_policy'."}
}

test_dms_vpc_endpoint_with_no_policy {
    result = deny with input as data.mock.no_policy
    result == {"AWS-DMS-M-4: DMS vpc endpoint policy is not defined for 'aws_vpc_endpoint.dms_vpc_endpoint_with_no_policy'."}
}

test_dms_with_no_vpc_endpoint {
    result = deny with input as data.mock.no_vpc_endpoint
    result == {"AWS-DMS-M-4: Resource 'aws_dms_replication_instance.test' is used and traffic should be restricted to DMS from VPC endpoint using servicename 'com.amazonaws.eu-central-1.dms' (create DMS VPC endpoint)"}
}
