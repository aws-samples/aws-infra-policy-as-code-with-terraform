package aws.ecr.m1

# Ensure that the immutable tags force you to update the image tag on each push to the image repository.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#image_tag_mutability

# Amazon ECR image tag mutability
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_ecr_repository"
}

is_tag_immutable_enabled(resource){
    resource.change.after.image_tag_mutability == "IMMUTABLE"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	not is_tag_immutable_enabled(resource)
	message := "AWS-ECR-M-1: ECR central repository should have 'image_tag_mutability' set to 'IMMUTABLE' for '%s'."
	reason := sprintf(message, [resource.address])
}
