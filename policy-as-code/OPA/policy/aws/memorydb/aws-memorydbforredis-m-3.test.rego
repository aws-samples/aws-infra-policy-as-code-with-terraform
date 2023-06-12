package aws.memorydbforredis.m3

message = {"AWS-MEMORYDB-FOR-REDIS-M-3: For user Authentication default ACL should not be accepted, Create custom ACL by using aws_memorydb_acl 'aws_memorydb_cluster.memorydb_for_redis'"}  

test_valid_referenced {
  result = deny with input as data.mock.valid_referenced
  count(result) == 0
} 

test_valid_constant {
  result = deny with input as data.mock.valid_constant
  count(result) == 0
}

test_invalid {
  result = deny with input as data.mock.invalid
  result == message
}
