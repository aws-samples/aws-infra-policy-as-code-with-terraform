package aws.sagemaker.m2

msg := {"AWS-SageMaker-M-2: Resource 'aws_sagemaker_notebook_instance.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}
domain_msg := {"AWS-SageMaker-M-2: Resource 'aws_sagemaker_domain.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}

test_valid_referenced {
    result = deny with input as data.mock.valid_referenced
    count(result) == 0
}

test_valid_constant {
    result = deny with input as data.mock.valid_constant
    count(result) == 0
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg
}

test_domain_default_settings {
    result = deny with input as data.mock.invalid_domain
    result == domain_msg
}

test_domain_valid_constant {
    result = deny with input as data.mock.valid_domain
    count(result) == 0
}
