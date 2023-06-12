package aws.acm.m2

# Certificate transparency must be enabled for all customer facing applications
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate#certificate_transparency_logging_preference

# Certificate Transparency Logging
# https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html#concept-transparency

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_acm_certificate"
}

is_certif_transparency_enabled(resource){
    resource.change.after.options[_].certificate_transparency_logging_preference == "ENABLED"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)

	not is_certif_transparency_enabled(resource)
	message := "AWS-ACM-M-2: CA should have certificate_transparency_logging_preference set to 'ENABLED' for '%s'."
    reason := sprintf(message, [resource.address])
}
