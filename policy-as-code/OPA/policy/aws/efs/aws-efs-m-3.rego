package aws.efs.m3

# Ensure that Amazon EFS file systems access policy is limited/restrictive and should not contain wildcard '*'.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system_policy#policy

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html
# https://docs.aws.amazon.com/efs/latest/ug/access-control-block-public-access.html

# .................................................
# Functions block
# .................................................

is_in_scope(resource, type){
    resource.mode == "managed"
    resource.type == type
    data.utils.is_resource_create_or_update(resource)
}

as_array(x) = [x] {not is_array(x)} else = x {true}

is_condition_present(resource) {
    json.unmarshal(resource.change.after.policy, doc)
	statement = as_array(doc.Statement)[_]
    statement["Condition"]
} else = false {
    true
}

is_principal_restricted(resource) {
    json.unmarshal(resource.change.after.policy, doc)
	statement = as_array(doc.Statement)[_]
    statement["Principal"]["AWS"] != "*"
} else = false {
    true
}

enforce_file_system_policy(service) {
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_efs_file_system_policy")

    config_resource := data.utils.find_configuration_resource(input, resource)
    resource_ref := config_resource.expressions.file_system_id.references[_]
    contains(service, resource_ref)
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_efs_file_system")

    not enforce_file_system_policy(resource.address)
    reason := sprintf("AWS-EFS-M-3: Resource '%s' file system does not have file system policy defined (make sure 'aws_efs_file_system_policy' resource is defined)", [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_efs_file_system_policy")

    not is_principal_restricted(resource)
    message := "AWS-EFS-M-3: Resource '%s' file system policy should have principal restricted (make sure 'Principal' should not have '*')"
    reason := sprintf(message, [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_efs_file_system_policy")

    not is_condition_present(resource)
    message := "AWS-EFS-M-3: Resource '%s' file system policy does not contain any non-public condition (make sure non-public 'Condition' argument is defined)"
    reason := sprintf(message, [resource.address])
}
