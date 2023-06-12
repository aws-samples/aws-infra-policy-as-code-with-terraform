package aws.sagemaker.m1

# Ensure that Amazon SageMaker Notebook instances are not persisted in git repositories.

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sagemaker_notebook_instance#default_code_repository

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html#cfn-sagemaker-notebookinstance-defaultcoderepository

supported_resource_types = ["aws_sagemaker_notebook_instance"]

# .................................................
# Functions block
# .................................................

is_in_scope(resource, types){
    resource.mode == "managed"
    resource.type == types[_]
    data.utils.is_resource_create_or_update(resource)
}

is_code_repo_not_set(resource) {
    repo := resource.change.after.default_code_repository
    is_null(repo)
} else = false {
    true
}

# .................................................
# Deny blocks
# .................................................

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource, supported_resource_types)

    not is_code_repo_not_set(resource)
    message := "AWS-SageMaker-M-1: Resource '%s' should not persist in git repositories (make sure 'default_code_repository' argument is not set)"
    reason := sprintf(message, [resource.address])
}
