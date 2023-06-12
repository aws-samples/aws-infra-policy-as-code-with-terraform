package aws.redshift.r2


test_not_compliant{
    result = deny with input as data.mock.notcompliant
    result == {"AWS-Redshift-R-2: Resource 'aws_redshift_cluster.notcompliant' must have 'automated_snapshot_retention_period' set to at least '1'."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
