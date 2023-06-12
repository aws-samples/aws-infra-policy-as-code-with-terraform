package aws.dms.m5

# Ensure that Amazon Database Migration Service (DMS) replication instances
#   have the Auto Minor Version Upgrade feature enabled

deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_dms_replication_instance"
	not value.expressions.auto_minor_version_upgrade.constant_value
	reason := sprintf("AWS-DMS-M-5: DMS instance '%s' must to be configured to enable minor engine upgrades", [value.address])
}
