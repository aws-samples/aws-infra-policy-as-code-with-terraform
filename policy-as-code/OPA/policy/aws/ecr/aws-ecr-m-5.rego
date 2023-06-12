package aws.ecr.m5

# Ensure lifecycle policy for image repository to automatically remove untagged or old container images
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy

# Amazon ECR lifecycle policies
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html


is_tagged_rule(rule){
    rule.action.type == "expire"
    rule.selection.tagStatus == "tagged"
    rule.selection.countType == "imageCountMoreThan"
    rule.selection.countNumber == 2
    count(rule.selection.tagPrefixList) > 0
}

is_any_rule(rule){
    rule.action.type == "expire"
    rule.selection.tagStatus == "any"
    rule.selection.countType == "imageCountMoreThan"
    rule.selection.countNumber == 2
}

as_array(x) = [x] {not is_array(x)} else = x {true}

is_valid_policy_rules_present(rules){
    some lifecycle_rule
    rule = rules[lifecycle_rule]
    is_any_rule(rule)
}else = true{
    some lifecycle_rule
    rule = rules[lifecycle_rule]
    is_tagged_rule(rule)
}else = false{
    true
}

is_in_scope(resource, type){
    resource.mode == "managed"
    change_actions := resource.change.actions
	change_actions[count(change_actions) - 1] == ["create", "update", "no-op"][_]
	resource.type == type
}

is_missing_policy(resource, name){
    not resource[name]
}

enforce_lifecycle_policy(service){
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_ecr_lifecycle_policy")
    config_resource := data.utils.find_configuration_resource(input, resource)
    resource_ref := config_resource.expressions.repository.references[_]
    contains(service, resource_ref)
}

get_error_message(resource) = message {
    is_missing_policy(resource.change.after, "policy")
	message := sprintf("AWS-ECR-M-5: ECR image lifecycle policy is not defined for '%s'.", [resource.address])
} else = message {
	json.unmarshal(resource.change.after.policy, doc)
    rules = as_array(doc.rules)
	not is_valid_policy_rules_present(rules)
	message := sprintf("AWS-ECR-M-5: ECR image lifecycle policy of deleting untagged images or deleting olderthan 2 tagged images is not defined for '%s'.", [resource.address])
}

deny[reason] {
    resource = input.resource_changes[_]
    is_in_scope(resource, "aws_ecr_repository")

    not enforce_lifecycle_policy(resource.address)
    reason := sprintf("AWS-ECR-M-5: ECR repository '%s' does not have image lifecycle policy rules defined.", [resource.address])
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_ecr_lifecycle_policy")

	reason := get_error_message(resource)
}