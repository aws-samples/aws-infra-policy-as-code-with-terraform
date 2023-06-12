package aws.efs.m3

condition_msg := {"AWS-EFS-M-3: Resource 'aws_efs_file_system_policy.policy' file system policy does not contain any non-public condition (make sure non-public 'Condition' argument is defined)"}
principal_msg := {"AWS-EFS-M-3: Resource 'aws_efs_file_system_policy.policy' file system policy should have principal restricted (make sure 'Principal' should not have '*')"}
enforce_msg := {"AWS-EFS-M-3: Resource 'aws_efs_file_system.test' file system does not have file system policy defined (make sure 'aws_efs_file_system_policy' resource is defined)"}

test_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_invalid_condition {
    result = deny with input as data.mock.invalid_condition
    result == condition_msg
}

test_invalid_principal {
    result = deny with input as data.mock.invalid_principal
    result == principal_msg
}

test_no_filesystem_policy {
    result = deny with input as data.mock.no_policy
    result == enforce_msg
}
