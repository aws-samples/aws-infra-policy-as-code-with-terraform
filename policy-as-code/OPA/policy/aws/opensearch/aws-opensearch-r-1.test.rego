package aws.opensearch.r1

msg:= {"AWS-OpenSearch-R-1: OpenSearch resource 'aws_opensearch_domain.example' must be enabled with advanced_security_options"}

test_valid{
    result = deny with input as data.mock.valid
    count(result)==0
}

test_invalid{
    result =  deny with input as data.mock.invalid
    msg==result
}

test_undefined{
    result =  deny with input as data.mock.undefined
    msg==result
}
