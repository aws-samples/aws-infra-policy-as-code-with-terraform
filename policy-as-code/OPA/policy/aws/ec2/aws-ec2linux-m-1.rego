package aws.ec2linux.m1

# Ensure that EC2 instance has no public IP address associated

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address

# AWS link to policy defitinio/explanation
# https://aws.amazon.com/premiumsupport/knowledge-center/ec2-associate-static-public-ip/

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_instance"
	data.utils.is_create_or_update(resource.change.actions)
	not resource.change.after.associate_public_ip_address == false

    reason := sprintf("AWS-EC2Linux-M-1: '%s' EC2 Linux instance should have 'associate_public_ip_address' parameter set to false", [resource.address])
}
