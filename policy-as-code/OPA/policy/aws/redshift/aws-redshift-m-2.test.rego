package aws.redshift.m2


test_not_compliant_no_parameter_group{
    result = deny with input as data.mock.notcompliant_no_parameter_group
    result == {"AWS-Redshift-M-2: Resource 'aws_redshift_cluster.notcompliant_no_parameter_group' is missing parameter group that specifies encryption settings."}
}

test_not_compliant_no_valid_parameter{
    result = deny with input as data.mock.notcompliant_no_valid_parameter
    result == {"AWS-Redshift-M-2: Resource 'aws_redshift_cluster.notcompliant_no_valid_parameter' parameter group must enable 'require_ssl' parameter."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
