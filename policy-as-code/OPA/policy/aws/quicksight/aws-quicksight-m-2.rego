package aws.quicksight.m2

# Ensure that QuickSight uses VPC Connection to data sources

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/quicksight_data_source#vpc_connection_arn

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/quicksight/latest/user/working-with-aws-vpc.html

AWS_SERVICES_LIST := ["amazon_elasticsearch", "athena", "aurora", "aurora_postgresql", "aws_iot_analytics", "rds", "redshift", "s3"]

if_aws_datasource_used(parameters) = services {
    services := [ds_source|ds_source := AWS_SERVICES_LIST[_]
    						count(parameters[ds_source]) > 0]
}

if_vpc_connection_enabled(resource) {
	resource.change.after.vpc_connection_properties[_].vpc_connection_arn
}

deny[reason] {
	resource := input.resource_changes[_]
	resource.mode == "managed"
	resource.type == "aws_quicksight_data_source"
	data.utils.is_create_or_update(resource.change.actions)
	count(if_aws_datasource_used(resource.change.after.parameters[_]))>0
	not if_vpc_connection_enabled(resource)
	reason := sprintf("AWS-QuickSight-M-2: '%s' is used and should have 'vpc_connection_arn' property set to arn of the connection", [resource.type])
}
