package aws.efs.m1

encrypted_msg := "AWS-EFS-M-1: Resource 'aws_efs_file_system.test' should have 'encrypted' argument set to 'true' to use customer managed keys (CMK) (make sure 'encrypted' argument is set to 'true')"
kms_msg := "AWS-EFS-M-1: Resource 'aws_efs_file_system.test' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"

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
    result == {encrypted_msg, kms_msg}
}

test_default_kms_key {
    result = deny with input as data.mock.default_kms
    result == {kms_msg}
}

test_invalid_kms_key {
    result = deny with input as data.mock.invalid_kms_key
    result == {kms_msg}
}
