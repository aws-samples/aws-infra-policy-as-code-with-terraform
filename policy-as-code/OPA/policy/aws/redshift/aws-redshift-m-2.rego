package aws.redshift.m2

# Ensure all user connections to Redshift clusters are encrypted by using "require_ssl" parameter

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_parameter_group

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/redshift/latest/mgmt/security-encryption-in-transit.html

# .................................................
# Functions block
# .................................................

is_in_scope(resource){
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_redshift_cluster"
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
		has_parameter_value(parameter, "require_ssl", "true")
	]) < 1
	msg := "AWS-Redshift-M-2: Resource '%s' parameter group must enable 'require_ssl' parameter."
}

get_error_message(resource) = msg {
	is_absent(resource.change.after, "cluster_parameter_group_name")
	msg := "AWS-Redshift-M-2: Resource '%s' is missing parameter group that specifies encryption settings."
} else = msg {
	parameter_group := get_parameter_group(resource.change.after.cluster_parameter_group_name)
	msg := validate_redshift_parameter_group(parameter_group)
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	message := get_error_message(resource)
	reason := sprintf(message, [resource.address])
}
