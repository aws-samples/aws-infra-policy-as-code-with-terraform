package aws.msk.m4

# AWS MSK Authentication should be set to IAM

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#client_authentication

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/msk/latest/developerguide/security_iam_service-with-iam.html

is_in_scope(resource) {
    resource.mode == "managed"
    data.utils.is_create_or_update(resource.change.actions)
    resource.type == "aws_msk_cluster"
}

is_auth_iam(resource){
    auth := resource.change.after.client_authentication[sasl]
    iam_status := auth.sasl[iam]  
    [path,val] := walk(iam_status.iam)
    val == true
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)
        
    not is_auth_iam(resource)
    message := "AWS-MSK-M-4: Authentication should be set to IAM for '%s'"
    reason := sprintf(message, [resource.address])
}
