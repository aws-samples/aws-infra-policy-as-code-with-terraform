package aws.ecr.m3

# Ensure that the ECR repository images scan on push is enabled on the central repo.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_scanning_configuration

# ECR image scanning
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_ecr_repository"
}

is_scan_on_push_enabled(resource){
    resource.change.after.image_scanning_configuration[_].scan_on_push == true
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_scan_on_push_enabled(resource)
	message := "AWS-ECR-M-3: ECR central repository should have 'scan_on_push' enabled for '%s'."
	reason := sprintf(message, [resource.address])
}
