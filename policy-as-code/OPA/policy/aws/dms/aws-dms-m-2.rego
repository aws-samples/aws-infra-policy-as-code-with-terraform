package aws.dms.m2

# Ensure the replication instance itself must not be publicly accessible.
#   https://registry.terraform.io/providers/hashicorp/aws/2.38.0/docs/resources/dms_replication_instance#argument-reference

msg := "AWS-DMS-M-2: DMS instance '%s' cannot be configured to be publicly accessible"

deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_dms_replication_instance"
	value.expressions.publicly_accessible.constant_value
	reason := sprintf(msg, [value.address])
}
