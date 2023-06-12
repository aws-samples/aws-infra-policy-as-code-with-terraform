package aws.datasync.m1

test_valid_datasync_location_s3_iam_role {
    result = deny with input as data.mock.valid_datasync_location_s3_iam_role_referenced
    count(result) == 0
}

test_valid_datasync_location_s3_iam_role_const_value {
    result = deny with input as data.mock.valid_datasync_location_s3_iam_const_value
    count(result) == 0
}

test_invalid_datasync_location_s3{
    result = deny with input as data.mock.invalid_datasync_location_s3
    msg = {"AWS-DataSync-M-1: Resource 'aws_datasync_location_s3.example' datasync s3 location, doesn't have a valid role arn configured."}
    result == msg
}
