package aws.dms.m5

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid_misssing {
	result = deny with input as data.mock.invalid[0]
	"AWS-DMS-M-5: DMS instance 'aws_dms_replication_instance.test_missing' must to be configured to enable minor engine upgrades" == result[_]
}

test_invalid_false {
	result = deny with input as data.mock.invalid[1]
	"AWS-DMS-M-5: DMS instance 'aws_dms_replication_instance.test_false' must to be configured to enable minor engine upgrades" == result[_]
}
