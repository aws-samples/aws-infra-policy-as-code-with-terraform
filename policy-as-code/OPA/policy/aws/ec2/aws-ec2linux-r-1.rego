package aws.ec2linux.r1

# Ensure that EC2 instance has security group attached and this group doesn't contain 0.0.0.0/0 as inbound rule

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#vpc_security_group_ids

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html

security_group_is_set(value) {
	count(value.expressions.vpc_security_group_ids.constant_value) > 0
} else {
	count(value.expressions.vpc_security_group_ids.references) > 0
} else = false {
	true
}

split_sg_id(sg_str) = [x |
	parts := split(sg_str, ".")
	x := parts[1]
]

if_open_rule(sg_ref) {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_security_group"
	resource.name == sg_ref
	resource.change.after.ingress[_].cidr_blocks[_] != "0.0.0.0/0"
}

get_correct_message(value) = msg {
	not security_group_is_set(value)
	msg := "AWS-EC2Linux-R-1: EC2 resource '%s' must have security groups attached"
} else = msg {
	sg_ref := split_sg_id(value.expressions.vpc_security_group_ids.references[_])[0]
	not if_open_rule(sg_ref)
	msg := "AWS-EC2Linux-R-1: EC2 resource '%s' security groups shall not have '0.0.0.0/0' in inbound rules"
}

get_error_message(resource) = msg {
	value := data.utils.find_configuration_resource(input, resource)
	msg := get_correct_message(value)
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_instance"
	data.utils.is_create_or_update(resource.change.actions)
	message := get_error_message(resource)

	reason := sprintf(message, [resource.type])
}
