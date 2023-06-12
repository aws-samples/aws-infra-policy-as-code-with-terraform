package aws.cloudwatch.m1

msg1 := {"AWS-CloudWatch-M-1: CloudWatch Log Group 'aws_cloudwatch_log_group.opa_log_group' log data should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}
msg2 := {"AWS-CloudWatch-M-1: KMS key 'aws_kms_key.opa_s3_key' must restrict the use of the key to only those AWS accounts or log groups you specify (set kms:EncryptionContext:aws:logs:arn condition in the key policy)"}

test_valid_concrete_key_value {
	result = deny with input as data.mock.valid.concrete_key_value
	count(result) == 0
}

test_valid_key_resource_reference {
	result = deny with input as data.mock.valid.key_resource_reference
	count(result) == 0
}

test_valid_has_unrelated_kms_key {
	result = deny with input as data.mock.valid.has_unrelated_kms_key
	count(result) == 0
}

test_key_missing {
	result = deny with input as data.mock.invalid.key_missing
    result == msg1
}

test_key_empty {
	result = deny with input as data.mock.invalid.key_empty
    result == msg1
}

test_kms_key_missing_encryption_context {
	result = deny with input as data.mock.invalid.kms_key_missing_encryption_context
	count(result) == 1
    result == msg2
}