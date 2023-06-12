package aws.memorydbforredis.m2

message = {"AWS-MEMORYDB-FOR-REDIS-M-2:Server side encryption must be enabled by using customer managed key 'aws_memorydb_cluster.memorydb_for_redis'"}

test_valid_kms_referenced {
  result = deny with input as data.mock.valid_kms_referenced
  count(result) == 0
} 

test_valid_kms_constant {
  result = deny with input as data.mock.valid_kms_constant
  count(result) == 0
} 

test_invalid {
  result = deny with input as data.mock.invalid
  result == message
}
