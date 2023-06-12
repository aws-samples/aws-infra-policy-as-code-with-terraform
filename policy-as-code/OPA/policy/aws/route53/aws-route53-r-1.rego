package aws.route53.r1

# Logging and monitoring controls should be created for route53 to review DNS queries being executed
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_resolver_query_log_config

# Resolver query logging
# https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_route53_resolver_query_log_config"
}

is_log_group_specified_in_changes(resource) {
	startswith(resource.change.after.destination_arn,"arn:aws:logs:")
} else {
	config_resource := data.utils.find_configuration_resource(input, resource)
	references := config_resource.expressions.destination_arn.references[_]
	contains(references,"aws_cloudwatch_log_group.")
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
	
	not is_log_group_specified_in_changes(resource)
	message := "AWS-Route53-R-1: Route53 resolver should have logging and monitoring controls enabled for '%s' with destination_arn parameter."
	reason := sprintf(message, [resource.address])
}
