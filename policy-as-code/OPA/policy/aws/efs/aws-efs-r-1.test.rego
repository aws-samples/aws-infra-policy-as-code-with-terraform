package aws.efs.r1

msg := {"AWS-EFS-R-1: Resource 'aws_efs_access_point.test' should have app-specific root directory configured (make sure 'root_directory' argument is defined) and should not use '/'"}

test_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_invalid {
    result = deny with input as data.mock.invalid
    result == msg
}

test_default_settings {
    result = deny with input as data.mock.default_settings
    result == msg
}
