package aws.acm.m1

# Ceritificate tagging must be enforced

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate#tags

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/acm/latest/userguide/tags.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_acm_certificate"
}

is_tags_enabled(resource){
    #detects both empty values for tags or no tags at all
    count(resource.change.after.tags_all) != 0
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_tags_enabled(resource)
    message := "AWS-ACM-M-1: CA should have tags defined for '%s'."
    reason := sprintf(message, [resource.address])
}
