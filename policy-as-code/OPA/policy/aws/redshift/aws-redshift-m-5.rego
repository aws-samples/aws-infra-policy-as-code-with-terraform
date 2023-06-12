package aws.redshift.m5

# Ensure that 'awsuser' is not used as 'master_username' for database access.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#master_username

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html

# .................................................
# Functions block
# .................................................

is_in_scope(resource){
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_redshift_cluster"
}

is_valid_master_user_name(resource){
	resource.change.after.master_username != "awsuser"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_valid_master_user_name(resource)
	message := "AWS-Redshift-M-5: Resource '%s' must not have 'awsuser' as  'master_username' (make sure to use a different username for 'master_username')."
	reason := sprintf(message, [resource.address])
}
