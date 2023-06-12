package aws.opensearch.m1

test_valid_existing_kms_key_arn {
    result = deny with input as data.mock.valid_kms_key_existing_arn
    count(result) == 0
}

test_valid_existing_kms_key_id {
    result = deny with input as data.mock.valid_kms_key_existing_id
    count(result) == 0
}

test_valid_new_kms_key {
    result = deny with input as data.mock.valid_new_kms_key
    count(result) == 0
}

test_undefined {
    result =  deny with input as data.mock.undefined
    msg := {"AWS-OpenSearch-M-1: OpenSearch resource 'aws_opensearch_domain.example' must be configured with encrypt_at_rest as true", "AWS-OpenSearch-M-3: OpenSearch resource 'aws_opensearch_domain.example' must set to use CMK KMS key for encryption at rest using kms_key_id"}
    msg == result
}

test_encryption_disabled {
    result =  deny with input as data.mock.encryption_disabled
    {"AWS-OpenSearch-M-1: OpenSearch resource 'aws_opensearch_domain.example' must be configured with encrypt_at_rest as true"} == result
}



test_invalid_no_kms_key {
    result =  deny with input as data.mock.invalid_no_kms_key
    {"AWS-OpenSearch-M-3: OpenSearch resource 'aws_opensearch_domain.example' must set to use CMK KMS key for encryption at rest using kms_key_id"} == result
}
