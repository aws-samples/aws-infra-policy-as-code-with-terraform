package aws.acm.m1

test_ca_defaults {
    result = deny with input as data.mock.aws_ca_non_compliant_default
    result == {"AWS-ACM-M-1: CA should have tags defined for 'aws_acm_certificate.aws_ca_non_compliant_default'."}
}


test_ca_non_compliant_tags_empty{
	result = deny with input as data.mock.aws_ca_non_compliant_tags_empty
	result == {"AWS-ACM-M-1: CA should have tags defined for 'aws_acm_certificate.aws_ca_non_compliant_tags_empty'."}
}

test_ca_compliant_tags {
    result = deny with input as data.mock.aws_ca_compliant_tags
    count(result) == 0
}
