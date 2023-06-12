package aws.dms.m4

# Ensure that DMS should have VPC endpoint to prevent network traffic leaving from the AWS network.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# Configure VPC endpoint for DMS
# https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#infrastructure-security

# Modify your Organization ID and DMS Endpoint service related to your region (eu-central-1 is used in this example)
ORG_ID := "o-123abcxxxx"
DMS_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.dms"

is_in_scope(resource, type) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

as_array(x) = [x] {not is_array(x)} else = x {true}

is_missing_policy(resource, name){
    not resource[name]
}

get_org_id(statement) = org_id {
    statement.Effect == "Deny"
    org_id := statement.Condition.StringNotEquals["aws:ResourceOrgID"]
}

is_least_privilege(statement) {
    org_id := as_array(get_org_id(statement))
    org_id == [ORG_ID]
}

is_valid_policy(resource) {
    json.unmarshal(resource.change.after.policy, doc)
	statement = as_array(doc.Statement)[_]
	is_least_privilege(statement)
}

get_error_message(resource) = message {
    is_missing_policy(resource.change.after, "policy")
	message := "AWS-DMS-M-4: DMS vpc endpoint policy is not defined for '%s'."
} else = message {
	not is_valid_policy(resource)
	message := "AWS-DMS-M-4: DMS vpc endpoint policy does not contain condition 'aws:ResourceOrgID' for '%s'."
}


deny[reason]{
    service = data.utils.find_service_resource(input, "aws_dms")
    count(service) > 0

    not data.aws.utils.is_service_vpc_endpoint_exists(input, DMS_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-DMS-M-4: Resource '%s' is used and traffic should be restricted to DMS from VPC endpoint using servicename '%s' (create DMS VPC endpoint)", [service[0], DMS_ENDPOINT_SERVICE_NAME])
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_vpc_endpoint")

    resource.change.after.service_name == DMS_ENDPOINT_SERVICE_NAME
    message := get_error_message(resource)
    reason := sprintf(message, [resource.address])
}
