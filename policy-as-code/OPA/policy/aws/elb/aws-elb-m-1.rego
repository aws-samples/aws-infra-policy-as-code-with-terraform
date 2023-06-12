package aws.elb.m1

# Ensure ELB access logs are enabled to log all calls made from ELB to backend

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#access_logs

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_lb"
}

is_access_logs_enabled(resource) {
	resource.change.after.access_logs[_].enabled == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_access_logs_enabled(resource)
	message := "AWS-ELB-M-1: ELB should have access_logs enabled for '%s'"
	reason := sprintf(message, [resource.address])
}
