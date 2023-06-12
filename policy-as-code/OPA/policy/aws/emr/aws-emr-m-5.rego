package aws.emr.m5

# Ensure that EMR Cluster EC2 instances must be hardened to CIS level 1

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster#bootstrap_action

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-bootstrap.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_emr_cluster"
}

is_invalid_path(action){
   action["path"] == ""
}

is_invalid_name(action){
   action["name"] == ""
}

is_bootstrap_actions_present(resource){
    action := resource.change.after.bootstrap_action[_]
    not is_invalid_path(action)
    not is_invalid_name(action)
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_bootstrap_actions_present(resource)
    reason := sprintf("AWS-EMR-M-5: EMR cluster '%s' must be hardened with bootstrap actions.", [resource.address])
}
