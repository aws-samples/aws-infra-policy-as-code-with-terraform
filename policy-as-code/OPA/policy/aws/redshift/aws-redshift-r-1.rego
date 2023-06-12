package aws.redshift.r1

# Ensure the AWS Redshift clusters are allowed version upgrades

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#allow_version_upgrade

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/cluster-versions.html

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
	not resource.change.after.allow_version_upgrade
	message := "AWS-Redshift-R-1: Resource '%s' must have 'allow_version_upgrade' set to true."
  reason := sprintf(message, [resource.address])
}
