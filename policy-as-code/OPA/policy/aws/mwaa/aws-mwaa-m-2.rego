package aws.mwaa.m2

# Ensure MWAA environment should be encrypted using customer managed keys (CMK)

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mwaa_environment#kms_key

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-mwaa-environment.html#cfn-mwaa-environment-kmskey


is_in_scope(resource) {
	resource.mode == "managed"
	resource.type == "aws_mwaa_environment"
	data.utils.is_create_or_update(resource.change.actions)
}

is_kms_key_defined(resource){
    key_id := resource.change.after.kms_key
    not is_null(key_id)
    not key_id == ""
    startswith(key_id, "arn:aws:kms:")
}else {
    resource.change.after_unknown.kms_key
}else = false{
    true
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_kms_key_defined(resource)
    reason := sprintf("AWS-MWAA-M-2: MWAA environment '%s' should be encrypted with CMK (make sure 'kms_key' argument is set).", [resource.address])
}
