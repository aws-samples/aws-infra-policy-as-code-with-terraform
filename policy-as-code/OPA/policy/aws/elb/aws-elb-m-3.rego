package aws.elb.m3

# Ensure ELB should be reachable only to internal network

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#internal

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-application-load-balancer.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_lb"
}

is_elb_configured_internal(resource) {
	resource.change.after.internal == true
} 

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_elb_configured_internal(resource)
	message := "AWS-ELB-M-3: ELB '%s' should be deployed using internal attribute set to true"
	reason := sprintf(message, [resource.address])
}
