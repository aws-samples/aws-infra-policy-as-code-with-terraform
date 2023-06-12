package aws.redshift.m3


test_not_compliant_encrypted{
    result = deny with input as data.mock.notcompliant_default
    result == {"AWS-Redshift-M-3: Resource 'aws_redshift_cluster.notcompliant_default' must be encrypted at rest.","AWS-Redshift-M-3: Resource 'aws_redshift_cluster.notcompliant_default' must be configured with a custom customer KMS key."}
}

test_not_compliant_kms{
    result = deny with input as data.mock.notcompliant_kms
    result == {"AWS-Redshift-M-3: Resource 'aws_redshift_cluster.notcompliant_kms' must be configured with a custom customer KMS key."}
}

test_compliant_referenced {
    result = deny with input as data.mock.compliant_referenced
    count(result) == 0
}
test_compliant_constant {
    result = deny with input as data.mock.compliant_constant
    count(result) == 0
}
