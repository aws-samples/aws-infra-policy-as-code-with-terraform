package aws.dms.m1

# Ensure that the data managed by 
#   AWS Database Migration Service (DMS) replication instances is encrypted 
#   with KMS Customer Master Keys (CMKs) instead of AWS managed-keys 
#   (default keys used by the DMS service when there are no customer-managed keys defined).

deny[reason] {
	[path, value] := walk(input.configuration)
	value.mode == "managed"
	value.type == "aws_dms_replication_instance"
	not value.expressions.kms_key_arn
	reason := sprintf("AWS-DMS-M-1: DMS instance '%s' must to be configured to use Customer Master Keys (CMKs) instead of the default AWS managed-keys for data encryption", [value.address])
}
