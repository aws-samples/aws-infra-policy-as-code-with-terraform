package aws.opensearch.m4

test_valid_logtypes {
    result = deny with input as data.mock.valid_logtypes
    count(result) == 0
}

test_invalid_logtypes {
    result = deny with input as data.mock.invalid_logtypes
    { "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have audit logs(log_type AUDIT_LOGS) enabled",
      "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have error logs(log_type ES_APPLICATION_LOGS) enabled"} == result
}

test_no_logs {
    result = deny with input as data.mock.no_logs
    { "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have audit logs(log_type AUDIT_LOGS) enabled",
      "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have error logs(log_type ES_APPLICATION_LOGS) enabled"} == result
}

test_audit_disabled {
    result = deny with input as data.mock.audit_disabled
    { "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have audit logs(log_type AUDIT_LOGS) enabled"} == result
}

test_error_disabled {
    result = deny with input as data.mock.error_disabled
    {"AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have error logs(log_type ES_APPLICATION_LOGS) enabled"} == result
}

test_audit_disabled_error_disabled {
    result = deny with input as data.mock.audit_disabled_error_disabled
    { "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have audit logs(log_type AUDIT_LOGS) enabled",
      "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have error logs(log_type ES_APPLICATION_LOGS) enabled"} == result
}

test_no_audit_log {
    result = deny with input as data.mock.no_audit_log
    { "AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have audit logs(log_type AUDIT_LOGS) enabled"} == result
} 

test_no_error_log {
    result = deny with input as data.mock.no_error_log
    {"AWS-OpenSearch-M-4: OpenSearch resource 'aws_opensearch_domain.example' must have error logs(log_type ES_APPLICATION_LOGS) enabled"} == result
}
