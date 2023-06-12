package aws.pl.m1

# Ensure that VPC service endpoint requires manual connection acceptance

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint_service#acceptance_required

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/vpc/latest/privatelink/configure-endpoint-service.html

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_vpc_endpoint_service"
	data.utils.is_create_or_update(resource.change.actions)
	not resource.change.after.acceptance_required == true

    reason := sprintf("AWS-PL-M-1: '%s' is used and should have 'acceptance_required' parameter set to true", [resource.type])
}
