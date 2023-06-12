package aws.lambda.r1

# Use AWS KMS CMK for server-side encryption of environment variables

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#kms_key_arn

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/whitepapers/latest/kms-best-practices/encrypting-lambda-environment-variables.html
# https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption

# ----------------------------------------------------------------------------------------------
# Functions block
# ----------------------------------------------------------------------------------------------

is_key_set(resource) {
    keyId := resource.change.after.kms_key_arn
    not is_null(keyId)
    not keyId == ""
    startswith(keyId, "arn:aws:kms:")
} else {
    resource.change.after_unknown.kms_key_arn == true
} else = false {
	true
}

# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_lambda_function"
	data.utils.is_resource_create_or_update(resource)
    count(resource.change.after.environment) > 0

    not is_key_set(resource)
	reason := sprintf("AWS-Lambda-R-1: Lambda '%s' environment variables should be encrypted with customer managed keys (CMK) (make sure 'kms_key_arn' argument is set)", [resource.address])
}
