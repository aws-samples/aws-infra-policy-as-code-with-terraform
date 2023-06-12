package aws.redshift.m5

test_not_compliant{
    result = deny with input as data.mock.notcompliant
    result == {"AWS-Redshift-M-5: Resource 'aws_redshift_cluster.notcompliant' must not have 'awsuser' as  'master_username' (make sure to use a different username for 'master_username')."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
