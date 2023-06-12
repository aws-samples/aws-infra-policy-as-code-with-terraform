package aws.redshift.m1


test_not_compliant{
    result = deny with input as data.mock.notcompliant
    result == {"AWS-Redshift-M-1: Resource 'aws_redshift_cluster.notcompliant' must not have public access."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
