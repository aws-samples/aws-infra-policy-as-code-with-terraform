package aws.service_name.policy_check

# {Provide policy description}

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/

# ----------------------------------------------------------------------------------------------
# Functions block
# ----------------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------------
# Deny block
# ----------------------------------------------------------------------------------------------

deny[reason] {
    #Initial block that resources are managed and what resource type
	resource := input.resource_changes[_]
	resource.mode == "managed"

    #Name of check we are interested in. replace with your example
    resource.type == $(terraform_service_name)

    #We are interested only in update or create actions.
	data.utils.is_resource_create_or_update(resource)

    #Code for you check

    #Not Code and reason
    not $_something
    reason := sprintf("AWS-service_name-check_number: Resource '%s' VALID EXPLANATION is resource valid and if not and why", [resource.address])
}
