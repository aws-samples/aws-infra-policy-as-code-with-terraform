package aws.elasticache.m5

# Ensure that Amazon ElastiCache cluster events are send to Amazon SNS.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#notification_topic_arn
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#notification_topic_arn

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/ECEvents.SNS.html

supported_resources = ["aws_elasticache_cluster", "aws_elasticache_replication_group"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_sns_topic_set(resource) {
    topicArn := resource.change.after.notification_topic_arn
    not is_null(topicArn)
    not topicArn == ""
    startswith(topicArn, "arn:aws:sns:")
} else {
    resource.change.after_unknown.notification_topic_arn == true
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, supported_resources)

    not is_sns_topic_set(resource)
    message := "AWS-ElastiCache-M-5: Resource '%s' should send cluster events to SNS topic (make sure 'notification_topic_arn' argument is set)"
    reason := sprintf(message, [resource.address])
}
