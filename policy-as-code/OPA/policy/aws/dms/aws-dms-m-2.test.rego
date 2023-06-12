package aws.dms.m2

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	result = deny with input as data.mock.invalid
	count(result) == 1

	"AWS-DMS-M-2: DMS instance 'aws_dms_replication_instance.value-true' cannot be configured to be publicly accessible" = result[_]
}
