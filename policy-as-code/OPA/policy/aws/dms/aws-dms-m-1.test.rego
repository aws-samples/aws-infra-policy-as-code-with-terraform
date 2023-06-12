package aws.dms.m1

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	result = deny with input as data.mock.invalid
	count(result) == 1
	"AWS-DMS-M-1: DMS instance 'aws_dms_replication_instance.test' must to be configured to use Customer Master Keys (CMKs) instead of the default AWS managed-keys for data encryption" == result[_]
}
