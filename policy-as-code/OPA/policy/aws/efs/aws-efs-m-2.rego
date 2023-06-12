package aws.efs.m2

# Ensure that Amazon EFS mount target security groups are configured and not the default one.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_mount_target#security_groups

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/efs/latest/ug/network-access.html

public_ips = ["0.0.0.0/0", "10.0.0.0/8"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, type){
    resource.mode == "managed"
    resource.type == type
    data.utils.is_resource_create_or_update(resource)
}

split_sg_id(sg_str) = [x |
    parts := split(sg_str, ".")
    x := parts[1]
]

is_non_restrictive_cidr(resource) {
   some rule, ip
   resource.change.after.ingress[rule].from_port == 2049
   resource.change.after.ingress[rule].cidr_blocks[ip] == public_ips[_]
}

is_valid_ingress_rule(sg_ref) {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_security_group")
    resource.name == sg_ref
    not is_non_restrictive_cidr(resource)
}

is_security_groups_referenced(resource) = sg_refs {
    config_resource := data.utils.find_configuration_resource(input, resource)
    sg_refs := config_resource.expressions.security_groups.references
}

is_security_groups_defined(resource) {
    count(resource.change.after.security_groups) > 0
} else {
    resource_ref := is_security_groups_referenced(resource)
    count(resource_ref) > 0
    sg_ref = split_sg_id(resource_ref[_])[0]
    is_valid_ingress_rule(sg_ref)
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_efs_mount_target")

    not is_security_groups_defined(resource)
    reason := sprintf("AWS-EFS-M-2: Resource '%s' should have security groups defined (make sure 'security_groups' argument is defined) and shall not have '0.0.0.0/0' in inbound rules and only allowed port has to be '2049'", [resource.address])
}
