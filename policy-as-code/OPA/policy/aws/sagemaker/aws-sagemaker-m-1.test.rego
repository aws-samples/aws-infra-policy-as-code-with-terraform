package aws.sagemaker.m1

msg := {"AWS-SageMaker-M-1: Resource 'aws_sagemaker_notebook_instance.test' should not persist in git repositories (make sure 'default_code_repository' argument is not set)"}

test_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_invalid {
    result = deny with input as data.mock.invalid
    result == msg
}
