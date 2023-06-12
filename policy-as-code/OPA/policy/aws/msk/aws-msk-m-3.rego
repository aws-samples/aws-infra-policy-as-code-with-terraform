package aws.msk.m3

# AWS MSK Kafka version should be above 2.5.1 to ensure Zookeeper encryption

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#kafka_version

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/msk/latest/developerguide/zookeeper-security.html
# https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_msk_cluster"
}

deny[reason] {
	resource := input.resource_changes[_]
	is_in_scope(resource)
			
	version := resource.change.after.kafka_version	
	version <= "2.5.1"
	message := "AWS-MSK-M-3: Kafka version should be above 2.5.1 to ensure Zookeeper encryption for resource '%s'"
	reason := sprintf(message, [resource.address])
}
