package aws.dynamodb.m1

# Ensures server side encryption using AWS customer managed key (CMK)

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#stream_enabled

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html

# ----------------------------------------------------------------------------------------------
# Functions block
# ----------------------------------------------------------------------------------------------
is_key_set(resource) {
    keyId := resource.change.after.server_side_encryption[_].kms_key_arn
    not is_null(keyId)
    not keyId == ""
    startswith(keyId, "arn:aws:kms:")
} else { 
	resource.change.after_unknown.server_side_encryption[_].kms_key_arn == true 
} 
else = false {
	true
}

# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_dynamodb_table"
	data.utils.is_resource_create_or_update(resource)
    not is_key_set(resource)
    reason := sprintf("AWS-DynamoDB-M-1: Resource '%s' kms_key_arn must be set to CMK ARN", [resource.address])
}
