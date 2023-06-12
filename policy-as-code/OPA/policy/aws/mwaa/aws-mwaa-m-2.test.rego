package aws.mwaa.m2

msg := {"AWS-MWAA-M-2: MWAA environment 'aws_mwaa_environment.example' should be encrypted with CMK (make sure 'kms_key' argument is set)."}

test_mwaa_env_valid_constant {
    result = deny with input as data.mock.valid_constant
    count(result) == 0
}

test_mwaa_env_valid_reference {
    result = deny with input as data.mock.valid_reference
    count(result) == 0
}

test_mwaa_env_invalid {
    result = deny with input as data.mock.invalid
    result == msg
}

