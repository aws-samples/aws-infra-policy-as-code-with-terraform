package aws.redshift.m3

# Ensure the AWS Redshift clusters are encrypted at rest and a dedicated CMK is being used

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#kms_key_id

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/security-server-side-encryption.html

# .................................................
# Functions block
# .................................................

is_in_scope(resource){
    resource.mode == "managed"
    data.utils.is_create_or_update(resource.change.actions)
    resource.type == "aws_redshift_cluster"
}

is_encrypted_enabled(resource) {
    resource.change.after.encrypted
} else = false {
    true
}

is_kms_key_set(resource) {
    config_resource := data.utils.find_configuration_resource(input, resource)
    key_id := config_resource.expressions.kms_key_id.constant_value
    contains(key_id, "arn:aws:kms:")
} else {
    config_resource := data.utils.find_configuration_resource(input, resource)
    key_refs := config_resource.expressions.kms_key_id.references
    count(key_refs) > 0
} else = false {
    true
}

deny[reason] {
   resource := input.resource_changes[_]
   is_in_scope(resource)
   not is_encrypted_enabled(resource)
   message := "AWS-Redshift-M-3: Resource '%s' must be encrypted at rest."
   reason := sprintf(message, [resource.address])
}
deny[reason] {
   resource := input.resource_changes[_]
   is_in_scope(resource)
   not is_kms_key_set(resource)
   message := "AWS-Redshift-M-3: Resource '%s' must be configured with a custom customer KMS key."
   reason := sprintf(message, [resource.address])
}
