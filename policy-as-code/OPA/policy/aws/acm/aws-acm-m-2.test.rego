package aws.acm.m2

test_ca_defaults {
    result = deny with input as data.mock.aws_ca_non_compliant_default
    result == {"AWS-ACM-M-2: CA should have certificate_transparency_logging_preference set to 'ENABLED' for 'aws_acm_certificate.aws_ca_non_compliant_default'."}
}

test_ca_non_compliant_disabled{
    result = deny with input as data.mock.aws_ca_non_compliant_disabled
    result == {"AWS-ACM-M-2: CA should have certificate_transparency_logging_preference set to 'ENABLED' for 'aws_acm_certificate.aws_ca_non_compliant_disabled'."}
}

test_ca_compliant_enabled {
    result = deny with input as data.mock.aws_ca_non_compliant_enabled
    count(result) == 0
}
