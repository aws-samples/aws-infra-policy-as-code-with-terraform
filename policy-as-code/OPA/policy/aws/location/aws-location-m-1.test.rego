package aws.location.m1

msg := {"AWS-Location-M-1: Resource 'aws_location_geofence_collection.test-collection' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)",
        "AWS-Location-M-1: Resource 'aws_location_tracker.test-tracker' should be encrypted with customer managed keys (CMK) (make sure 'kms_key_id' argument is set)"}

test_valid_kms_key_referenced {
    result = deny with input as data.mock.valid_kms_key_referenced
    count(result) == 0
}

test_valid_kms_key_constant {
    result = deny with input as data.mock.valid_kms_key_constant
    count(result) == 0
}

test_invalid_kms_key_not_set{
    result = deny with input as data.mock.invalid_kms_key_not_set
    result == msg
}