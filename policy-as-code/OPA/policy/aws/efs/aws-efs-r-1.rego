package aws.efs.r1

# Ensure that Amazon EFS file system access point uses app specific directory instead of systems root directory.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_access_point#root_directory

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html#enforce-root-directory-access-point

# .................................................
# Functions block
# .................................................

is_in_scope(resource, type){
    resource.mode == "managed"
    resource.type == type
    data.utils.is_resource_create_or_update(resource)
}

is_root_directory_configured(resource) {
    resource.change.after.root_directory[_].path != "/"
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_efs_access_point")

    not is_root_directory_configured(resource)
    reason := sprintf("AWS-EFS-R-1: Resource '%s' should have app-specific root directory configured (make sure 'root_directory' argument is defined) and should not use '/'", [resource.address])
}
