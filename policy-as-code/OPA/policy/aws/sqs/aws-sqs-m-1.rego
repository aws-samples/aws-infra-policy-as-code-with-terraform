package aws.sqs.m1

# Check if SQS queue uses KMS or SSE.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue#server-side-encryption-sse

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-key-management.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_resource_create_or_update(resource)
	resource.type == "aws_sqs_queue"
}

is_kms_key_id_defined(resource) {
	count(resource.change.after.kms_master_key_id) > 5
	contains(resource.change.after.kms_master_key_id, "arn:aws:kms:")
} else {
	resource.change.after.sqs_managed_sse_enabled == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_kms_key_id_defined(resource)
	reason := sprintf("AWS-SQS-M-1: SQS queue '%s' must be configured with customer KMS key or Server side encryption", [resource.address])
}