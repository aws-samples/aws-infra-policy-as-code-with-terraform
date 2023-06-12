package aws.emr.m3

# Ensure that EMR Cluster logs should be collected in dedicated S3 bucket.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster#log_uri

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html


is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_emr_cluster"
}

is_valid_log_uri(resource){
   value := resource.change.after.log_uri
   regex.match("s3://*", value)
}

deny[reason]{
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_valid_log_uri(resource)
    reason := sprintf("AWS-EMR-M-3: EMR cluster '%s' logs must be sent to S3 bucket.", [resource.address])
}
