package aws.redshift.m4


test_not_compliant_logging_attribute{
    result = deny with input as data.mock.notcompliant_logging_attribute
    result == {"AWS-Redshift-M-4: Resource 'aws_redshift_cluster.notcompliant_logging_attribute' must have 'logging.enable' set to true."}
}

test_not_compliant_no_parameter_group{
    result = deny with input as data.mock.notcompliant_no_parameter_group
    result == {"AWS-Redshift-M-4: Resource 'aws_redshift_cluster.notcompliant_no_parameter_group' is missing parameter group that specifies user activity logging."}
}

test_not_compliant_no_valid_parameter{
    result = deny with input as data.mock.notcompliant_no_valid_parameter
    result == {"AWS-Redshift-M-4: Resource 'aws_redshift_cluster.notcompliant_no_valid_parameter' parameter group must enable user activity logging."}
}

test_not_compliant_not_s3_destination{
    result = deny with input as data.mock.notcompliant_not_s3_destination
    result == {"AWS-Redshift-M-4: Resource 'aws_redshift_cluster.notcompliant_not_s3_destination' must have s3 bucket as logs destination."}
}

test_compliant {
    result = deny with input as data.mock.compliant
    count(result) == 0
}
