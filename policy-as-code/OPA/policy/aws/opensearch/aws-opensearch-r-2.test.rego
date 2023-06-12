package aws.opensearch.r2

msg:={"AWS-OpenSearch-R-2: OpenSearch resource 'aws_opensearch_domain.example' domain endpoint option enforce_https should not be set to false"}

test_valid {
    result = deny with input as data.mock.valid
    count(result)==0
}

test_invalid {
    result = deny with input as data.mock.invalid
    msg==result
}

test_undefined {
    result = deny with input as data.mock.undefined
    msg==result
}
