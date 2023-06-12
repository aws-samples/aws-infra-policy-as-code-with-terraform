package aws.elb.m2

# Ensure ELB target group connection termination is set to false

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group#connection_termination

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_lb_target_group"
}

is_conn_termination_disabled(resource) {
	resource.change.after.connection_termination == false
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_conn_termination_disabled(resource)
	message := "AWS-ELB-M-2: ELB target group '%s' should be configured with connection_termination set to false"
	reason := sprintf(message, [resource.address])
}
