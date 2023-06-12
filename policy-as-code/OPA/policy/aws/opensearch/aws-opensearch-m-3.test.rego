package aws.opensearch.m3

test_valid_node_encryption_configuration {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_invalid_node_encryption_configuration {
    result =  deny with input as data.mock.invalid
    {"AWS-OpenSearch-M-3: OpenSearch resource 'aws_opensearch_domain.example' must use node to node encryption"} == result
}

test_undefined_node_encryption_configuration { 
    result = deny with input as data.mock.undefined
    {"AWS-OpenSearch-M-3: OpenSearch resource 'aws_opensearch_domain.example' must use node to node encryption"} == result
}
