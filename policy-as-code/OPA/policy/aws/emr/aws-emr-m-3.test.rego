package aws.emr.m3

test_valid_emr_logging {
    result = deny with input as data.mock.valid_emr_logging
    count(result) == 0
}

test_invalid_emr_logging{
    result = deny with input as data.mock.invalid_emr_logging
    msg = {"AWS-EMR-M-3: EMR cluster 'aws_emr_cluster.cluster' logs must be sent to S3 bucket."}
    result == msg
}

test_empty_emr_logging{
    result = deny with input as data.mock.empty_log_uri
    msg = {"AWS-EMR-M-3: EMR cluster 'aws_emr_cluster.cluster' logs must be sent to S3 bucket."}
    result == msg
}
