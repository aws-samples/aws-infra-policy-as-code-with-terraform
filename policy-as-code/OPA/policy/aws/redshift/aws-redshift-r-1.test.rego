package aws.redshift.r1


test_not_compliant{
    result = deny with input as data.mock.notcompliant
    result == {"AWS-Redshift-R-1: Resource 'aws_redshift_cluster.notcompliant' must have 'allow_version_upgrade' set to true."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
