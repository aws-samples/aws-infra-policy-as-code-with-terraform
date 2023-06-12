package aws.redshift.r2

# Ensure the AWS Redshift clusters have automated snapshots enabled

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#automated_snapshot_retention_period

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html#about-automated-snapshots

# .................................................
# Functions block
# .................................................

is_in_scope(resource){
    resource.mode == "managed"
    data.utils.is_create_or_update(resource.change.actions)
    resource.type == "aws_redshift_cluster"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not resource.change.after.automated_snapshot_retention_period > 0
	message := "AWS-Redshift-R-2: Resource '%s' must have 'automated_snapshot_retention_period' set to at least '1'."
  reason := sprintf(message, [resource.address])
}
