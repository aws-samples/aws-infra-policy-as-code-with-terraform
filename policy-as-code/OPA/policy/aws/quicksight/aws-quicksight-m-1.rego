package aws.quicksight.m1

# Ensure that QuickSight uses SSL to communicate to data sources

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/quicksight_data_source#disable_ssl

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/quicksight/latest/user/data-encryption-in-transit.html

if_ssl_enabled(resource) {
	resource.change.after.ssl_properties[_].disable_ssl == false
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_quicksight_data_source"
	data.utils.is_create_or_update(resource.change.actions)
	not if_ssl_enabled(resource)

    reason := sprintf("AWS-QuickSight-M-1: '%s' is used and should have 'disable_ssl' property set to false", [resource.type])
}
