package aws.ec2linux.m2

# Ensure that EC2 instance uses IMDSv2 metadata service version

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#http_tokens

# AWS link to policy defitinio/explanation
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

valid_metadata(resource) {
    resource.change.after.metadata_options[_].http_tokens == "required"
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_instance"
	data.utils.is_create_or_update(resource.change.actions)
	not valid_metadata(resource)

    reason := sprintf("AWS-EC2Linux-M-2: '%s' EC2 Linux instance should have 'http_tokens' parameter set to required", [resource.address])
}
