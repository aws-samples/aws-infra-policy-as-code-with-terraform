package aws.emr.m1

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid_missing_security_configuration {
	result = deny with input as data.mock.invalid.missing_security_configuration
	result == {"AWS-EMR-M-1: EMR cluster 'aws_emr_cluster.missing_security_configuration' must include reference to ERM security configuration"}
}

test_invalid_security_encrypt_in_transit_false {
	result = deny with input as data.mock.invalid.security_configuration_encrypt_in_transit_false
	result == {"AWS-EMR-M-1: EMR security configuration 'aws_emr_security_configuration.emr_security_config' must enable data encryption in transit"}
}

test_invalid_security_encrypt_at_rest_false {
	result = deny with input as data.mock.invalid.security_configuration_encrypt_at_rest_false
	result == {"AWS-EMR-M-1: EMR security configuration 'aws_emr_security_configuration.emr_security_config' must enable data encryption at rest"}
}

test_invalid_security_encrypt_ebs_false {
	result = deny with input as data.mock.invalid.security_configuration_encrypt_ebs_false
	result == {"AWS-EMR-M-1: EMR security configuration 'aws_emr_security_configuration.emr_security_config' must enable EBS encryption at rest"}
}
