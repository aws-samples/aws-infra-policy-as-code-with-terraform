package aws.cloudwatch.m1

# CloudWatch log data should be encrypted with customer managed keys (CMK).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id

# Restrict the use of the CMK to only those AWS accounts or log groups you specify
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html

is_key_set(resource) {
    keyId := resource.change.after.kms_key_id
    not is_null(keyId)
    not keyId == ""
    startswith(keyId, "arn:aws:kms:")
} else {
    resource.change.after_unknown.kms_key_id == true
} else = false {
	true
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_cloudwatch_log_group"
	data.utils.is_resource_create_or_update(resource)

    not is_key_set(resource)
	reason := sprintf("AWS-CloudWatch-M-1: CloudWatch Log Group '%s' log data should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)", [resource.address])
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_kms_key"
	data.utils.is_resource_create_or_update(resource)

    policyString := resource.change.after.policy
    policy := json.unmarshal(policyString)
    statement := policy.Statement[_]
    statement.Principal.Service == "logs.amazonaws.com"

    not statement.Condition.ArnEquals["kms:EncryptionContext:aws:logs:arn"]
	reason := sprintf("AWS-CloudWatch-M-1: KMS key '%s' must restrict the use of the key to only those AWS accounts or log groups you specify (set kms:EncryptionContext:aws:logs:arn condition in the key policy)", [resource.address])
}