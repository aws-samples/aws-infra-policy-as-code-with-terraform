package aws.dms.m3

# Ensure use of secure channel for database migration.
#   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dms_endpoint
#   https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL.Limitations
#   https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-sslmode

within(arr, elem) {
	arr[_] = elem
} else = false {
	true
}

get_attr(object, attribute, default_value) = value {
	not object[attribute]
	value := default_value
} else = value {
	is_null(object[attribute])
	value := default_value
} else = value {
	value := object[attribute]
}

deny[reason] {
	no_ssl_services = ["s3", "redshift"]
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_dms_endpoint"
	resource.change.actions[count(resource.change.actions) - 1] == ["create", "update"][i]
	not within(no_ssl_services, resource.change.after.engine_name)
	not within(["require", "verify-ca", "verify-full"], get_attr(resource.change.after, "ssl_mode", "none"))
	reason := sprintf("AWS-DMS-M-3: DMS endpoint '%s' must be set to use a secure channel for database migration", [resource.address])
}
