package aws.emr.m2

# Ensure that EMR should have VPC endpoint to prevent network traffic leaving from the AWS network.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/emr/latest/ManagementGuide/interface-vpc-endpoint.html
# https://docs.aws.amazon.com/general/latest/gr/emr.html#emr_region

# Modify your EMR EC2 and EMR EKS Endpoint service related to your region (eu-central-1 is used in this example)
EMR_EC2_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.elasticmapreduce"
EMR_EKS_ENDPOINT_SERVICE_NAME := "com.amazonaws.eu-central-1.emr-containers"

as_array(x) = [x] {not is_array(x)} else = x {true}

is_missing_policy(resource, name){
    not resource[name]
}

is_in_scope(resource, type) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == type
}

is_resources_listed(statement){
    not as_array(statement["Resource"]) == ["*"]
}

get_error_message(resource) = message {
    is_missing_policy(resource.change.after, "policy")
	message := "AWS-EMR-M-2: VPC endpoint policy is not defined for '%s'."
} else = message {
	json.unmarshal(resource.change.after.policy, doc)
    statement = as_array(doc.Statement)[_]
	not is_resources_listed(statement)
	message := "AWS-EMR-M-2: EMR vpc endpoint policy least privilege for resources is not used for '%s'."
}

deny[reason]{
    service = data.utils.find_service_resource(input, "aws_emr_cluster")
    count(service) > 0

    not data.aws.utils.is_service_vpc_endpoint_exists(input, EMR_EC2_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-EMR-M-2: Resource '%s' is used and traffic should be restricted to EMR from VPC endpoint using servicename '%s' (create EMR EC2 VPC endpoint)", [service[0], EMR_EC2_ENDPOINT_SERVICE_NAME])
}

deny[reason]{
    service = data.utils.find_service_resource(input, "aws_emrcontainers")
    count(service) > 0

    not data.aws.utils.is_service_vpc_endpoint_exists(input, EMR_EKS_ENDPOINT_SERVICE_NAME)
    reason := sprintf("AWS-EMR-M-2: Resource '%s' is used and traffic should be restricted to EMR from VPC endpoint using servicename '%s' (create EMR EKS VPC endpoint)", [service[0], EMR_EKS_ENDPOINT_SERVICE_NAME])
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_vpc_endpoint")
    resource.change.after.service_name == EMR_EC2_ENDPOINT_SERVICE_NAME

    message := get_error_message(resource)
    reason := sprintf(message, [resource.address])
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource, "aws_vpc_endpoint")
    resource.change.after.service_name == EMR_EKS_ENDPOINT_SERVICE_NAME

    message := get_error_message(resource)
    reason := sprintf(message, [resource.address])
}
