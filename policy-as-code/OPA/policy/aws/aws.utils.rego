package aws.utils

# Checks if VPC Endpoint exists for the service
is_service_vpc_endpoint_exists(plan, service_name) {
    resource := plan.resource_changes[_]
	resource.mode == "managed"
    resource.type == "aws_vpc_endpoint"
    resource.change.after.service_name == service_name # this will also be false on delete action
} else = false {
    true
}