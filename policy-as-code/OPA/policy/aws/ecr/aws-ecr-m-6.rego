package aws.ecr.m6

# Ensure that VPC endpoint must have policy allowing only to company operated ECR repositories.
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html#ecr-setting-up-vpc-create

# Control access to services using VPC endpoint policies
# https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html#vpc-endpoint-policies


# Modify your ECR Endpoint service related to your region (eu-central-1 is used in this example)
ECR_API_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.ecr.api"
ECR_DKR_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.ecr.dkr"

# Please modify as use your repository tags appropriately in Lines 25 and 28
# Tag used in this example: `ArtifactoryScanCompleted: Yes`

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_vpc_endpoint"
}

as_array(x) = [x] {not is_array(x)} else = x {true}

is_missing_policy(resource, name){
    not resource[name]
}

is_resource_condition_present(statement){
    statement.Effect == "Allow"
    # Please modify and use your repository tags appropriately
    statement["Condition"]["StringEquals"]["ecr:ResourceTag/ArtifactoryScanCompleted"] == "Yes"
} else {
    statement.Effect == "Allow"
    # Please modify and use your repository tags appropriately
    statement["Condition"]["StringEquals"]["aws:ResourceTag/ArtifactoryScanCompleted"] == "Yes"
}else = false{
    true
}

get_error_message(resource) = message {
    is_missing_policy(resource.change.after, "policy")
	message := "AWS-ECR-M-6: ECR vpc endpoint policy is not defined for '%s'."
} else = message {
	json.unmarshal(resource.change.after.policy, doc)
	statement = as_array(doc.Statement)[_]
	not is_resource_condition_present(statement)
	message := "AWS-ECR-M-6: ECR vpc endpoint policy does not contain condition 'ecr:ResourceTag/ArtifactoryScanCompleted' for '%s'."
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource)
    resource.change.after.service_name == ECR_DKR_ENDPOINT_SERVICE_NAME
    message := get_error_message(resource)
    reason := sprintf(message, [resource.address])
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource)
    resource.change.after.service_name == ECR_API_ENDPOINT_SERVICE_NAME
    message := get_error_message(resource)
    reason := sprintf(message, [resource.address])
}
