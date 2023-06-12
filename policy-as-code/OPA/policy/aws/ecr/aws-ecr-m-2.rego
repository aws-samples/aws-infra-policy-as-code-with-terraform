package aws.ecr.m2

# Access to ECR repository should be limited to user/services needed via either IAM or resource policy ('*' shouldn't be used in the access policy).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy

# Amazon ECR repository policies
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html


as_array(x) = [x] {not is_array(x)} else = x {true}

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_ecr_repository_policy"
}

is_principalorgid_condition_present(condition){
	some org
	org_id := as_array(condition["StringEquals"]["aws:PrincipalOrgID"])[org]
	regex.match("o-[a-z0-9]+", org_id)
}

is_principal_least_privilege(statement){
	statement["Principal"]=="*"
    	statement["Condition"]
	is_principalorgid_condition_present(statement["Condition"])
}else {
	as_array(statement["Principal"]["AWS"])==["*"]
    	statement["Condition"]
	is_principalorgid_condition_present(statement["Condition"])
}else {
	as_array(statement["Principal"]["Service"])==["*"]
    	statement["Condition"]
	is_principalorgid_condition_present(statement["Condition"])
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	json.unmarshal(resource.change.after.policy, doc)
	statement = as_array(doc.Statement)[_]
	not is_principal_least_privilege(statement)
	message := "AWS-ECR-M-2: ECR central repository resource policy should use least privilege permissions for '%s'."
	reason := sprintf(message, [resource.address])
}
