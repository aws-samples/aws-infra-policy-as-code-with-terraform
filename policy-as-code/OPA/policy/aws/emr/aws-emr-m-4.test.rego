package aws.emr.m4

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	results = deny with input as data.mock.invalid
	endpoints := [
		"aws_emr_cluster.missing-emr_managed_master_security_group",
		"aws_emr_cluster.missing-emr_managed_slave_security_group",
		"aws_emr_cluster.with_constant_id",
		"aws_emr_cluster.no_ec2_attributes",
	]

	messages := {x | x := sprintf("AWS-EMR-M-4: EMR cluster '%s' must use custom security groups", [endpoints[_]])}
	messages == results
}

test_get_attr_null {
	get_attr({"null": null}, "null", true)
}
