package aws.redshift.m4

# Ensure the AWS Redshift clusters have user activity logging enabled

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#logging
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_parameter_group

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html

# .................................................
# Functions block
# .................................................

is_in_scope(resource){
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_redshift_cluster"
}

is_logging_enabled(resource){
	resource.change.after.logging[_].enable
}

is_absent(object, parameter) {
	not object[parameter]
} else = false {
	true
}

get_parameter_group(name) = parameter_group {
	[path, value] = walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_redshift_parameter_group"
  value.expressions.name.constant_value == name
	parameter_group := value
}

has_parameter_value(parameter, name, value) {
	parameter.name.constant_value == name
	parameter.value.constant_value == value
} else = false {
	true
}

validate_redshift_parameter_group(parameter_group) = msg {
	count([parameter |
		parameter := parameter_group.expressions.parameter[_]
		has_parameter_value(parameter, "enable_user_activity_logging", "true")
	]) < 1
	msg := "AWS-Redshift-M-4: Resource '%s' parameter group must enable user activity logging."
}

is_s3_destination (resource){
	config_resource := data.utils.find_configuration_resource(input, resource)
	contains(config_resource.expressions.logging[_].bucket_name.references[_],"aws_s3_bucket")
}

get_error_message(resource) = msg {
	not is_logging_enabled(resource)
	msg := "AWS-Redshift-M-4: Resource '%s' must have 'logging.enable' set to true."
} else = msg {
	is_absent(resource.change.after, "cluster_parameter_group_name")
	msg := "AWS-Redshift-M-4: Resource '%s' is missing parameter group that specifies user activity logging."
} else = msg {
	parameter_group := get_parameter_group(resource.change.after.cluster_parameter_group_name)
	msg := validate_redshift_parameter_group(parameter_group)
} else = msg {
	not is_s3_destination(resource)
	msg := "AWS-Redshift-M-4: Resource '%s' must have s3 bucket as logs destination."
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	message := get_error_message(resource)
	reason := sprintf(message, [resource.address])
}
