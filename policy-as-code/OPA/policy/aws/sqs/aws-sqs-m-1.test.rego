package aws.sqs.m1

msg := {"AWS-SQS-M-1: SQS queue 'aws_sqs_queue.sqs-queue' must be configured with customer KMS key or Server side encryption"}

test_valid_kms_key_id {
	result = deny with input as data.mock.valid.kms_key_id
	count(result) == 0
}

test_valid_deny_policy {
	result = deny with input as data.mock.valid.managed_sse
	count(result) == 0
}

test_invalid_no_policy {
	result = deny with input as data.mock.invalid
	count(result) == 1
    result == msg
}
