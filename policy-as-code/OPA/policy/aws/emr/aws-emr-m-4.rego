package aws.emr.m4

# Ensures usages of custom security groups for EMR cluster

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster


get_attr(object, attribute, default_value) = value {
	not object[attribute]
	value := default_value
} else = value {
	is_null(object[attribute])
	value := default_value
} else = value {
	value := object[attribute]
}

contains_security_groups(ec2_attributes) {
	ec2_attribute = ec2_attributes[_]
	ec2_attribute.emr_managed_master_security_group.references
	ec2_attribute.emr_managed_slave_security_group.references
} else = false {
	true
}

deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_emr_cluster"

	ec2_attributes = get_attr(value.expressions, "ec2_attributes", [])

	not contains_security_groups(ec2_attributes)
	reason := sprintf("AWS-EMR-M-4: EMR cluster '%s' must use custom security groups", [value.address])
}
