package aws.datasync.m1

# Ensure S3 location specifies predefined role
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/datasync_location_s3

# Cconfiguring an IAM role to access your Amazon S3 bucket for DataSync
# https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-role-manually

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_datasync_location_s3"
}

is_not_null_or_blank(role_arn){
	not is_null(role_arn)
	not role_arn == ""
}

is_valid_configuration(resource){
    role_arn := resource.change.after.s3_config[_].bucket_access_role_arn
    is_not_null_or_blank(role_arn)
    role_arn_pattern := "arn:aws:iam::[0-9]{12}:role\/.*"
    regex.match(role_arn_pattern, role_arn)
}else {
    resource.change.after_unknown.s3_config[_].bucket_access_role_arn == true
    config_resource := data.utils.find_configuration_resource(input, resource)
    references := config_resource.expressions.s3_config[_].bucket_access_role_arn.references
    count(references)>0
}else = false{
    true
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_valid_configuration(resource)
    reason := sprintf("AWS-DataSync-M-1: Resource '%s' datasync s3 location, doesn't have a valid role arn configured.", [resource.address])
}
