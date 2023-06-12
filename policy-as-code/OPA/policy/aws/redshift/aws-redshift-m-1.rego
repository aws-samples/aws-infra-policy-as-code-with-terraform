package aws.redshift.m1

# Ensure the AWS Redshift clusters are not be publicly accessible

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#publicly_accessible

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/iam-redshift-user-mgmt.html

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
	resource.change.after.publicly_accessible
	message := "AWS-Redshift-M-1: Resource '%s' must not have public access."
	reason := sprintf(message, [resource.address])
}
