package aws.route53.r1

test_route53_compliant_cloudwatch_logs_hard_coded {
	result = deny with input as data.mock.route53_compliant_logs_hard_coded
	count(result) == 0
}

test_route53_compliant_logs_cloudwatch_logs_referenced {
	result = deny with input as data.mock.route53_compliant_logs_referenced
	count(result) == 0
}

test_route53_non_compliant_logs_s3_hard_coded {
	result = deny with input as data.mock.route53_non_compliant_logs_hard_coded
	result == {"AWS-Route53-R-1: Route53 resolver should have logging and monitoring controls enabled for 'aws_route53_resolver_query_log_config.route53_non_compliant_logs_hard_coded' with destination_arn parameter."}
}

test_route53_non_compliant_logs_s3_referenced {
	result = deny with input as data.mock.route53_non_compliant_logs_referenced
	result == {"AWS-Route53-R-1: Route53 resolver should have logging and monitoring controls enabled for 'aws_route53_resolver_query_log_config.route53_non_compliant_logs_referenced' with destination_arn parameter."}
}


