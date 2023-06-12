package aws.elb.m4

# Ensure connections to LB and from LB to instances are encrypted

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group

# ELB listeners
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
# https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html

# ELB Target Groups
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html
# https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == ["aws_lb_listener","aws_lb_target_group"][_]
}

is_encrypt_in_transit_enabled(resource) {
	upper(resource.change.after.protocol) == "HTTPS"
} else { 
	upper(resource.change.after.protocol) == "TLS"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_encrypt_in_transit_enabled(resource)
	message := "AWS-ELB-M-4: ELB listener protocol and target group protocol should bet set to HTTPS/TLS '%s'"
	reason := sprintf(message, [resource.address])
}
