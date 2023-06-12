package aws.opensearch.m2

msg:= {"AWS-OpenSearch-M-2: OpenSearch resource 'aws_opensearch_domain.example' must be deployed in VPC by setting vpc_options subnet_ids"}

test_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_valid_subnet_reference {
    result = deny with input as data.mock.valid_subnet_reference
    count(result) == 0
}

test_invalid_empty_subnet_ids {
    result =  deny with input as data.mock.invalid_empty_subnet_ids
    msg == result
}

test_invalid_undefined_subnet_ids {
    result =  deny with input as data.mock.invalid_undefined_subnet_ids
    msg == result
}

test_invalid_undefined_vpc_options {
    result =  deny with input as data.mock.invalid_undefined_vpc_options
    msg == result
}
