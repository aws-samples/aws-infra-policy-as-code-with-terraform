package aws.msk.m2

# MSK: enable server side encryption using customer managed key (CMK) and not the default AWS CMK

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html


deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_msk_cluster"
	keys := value.expressions.encryption_info[encryption_at_rest_kms_key_arn]
    not keys.encryption_at_rest_kms_key_arn.references
	reason := sprintf("AWS-MSK-M-2: MSK cluster '%s' should use a CMK", [value.address])
}
