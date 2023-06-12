package aws.sagemaker.m2

# Ensure that Amazon SageMaker Notebook instances storage volumes are encrypted at rest using bank CMK.
# Ensure that EFS volumes attached to the Amazon SageMaker domain are encrypted at rest using bank CMK.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sagemaker_notebook_instance#kms_key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest-nbi.html

supported_resource_types = ["aws_sagemaker_notebook_instance", "aws_sagemaker_domain"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_kms_key_set(resource) {
    keyId := resource.change.after.kms_key_id
    not is_null(keyId)
    not keyId == ""
    startswith(keyId, "arn:aws:kms:")
} else {
    resource.change.after_unknown.kms_key_id == true
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, supported_resource_types)

    not is_kms_key_set(resource)
    message := "AWS-SageMaker-M-2: Resource '%s' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"
    reason := sprintf(message, [resource.address])
}
