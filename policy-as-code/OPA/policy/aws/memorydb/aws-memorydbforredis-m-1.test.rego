package aws.memorydbforredis.m1

message = {"AWS-MEMORYDB-FOR-REDIS-M-1:TLS must be enabled while creating MemoryDB Cluster 'aws_memorydb_cluster.memorydb_for_redis'"}

test_valid {
  result = deny with input as data.mock.valid
  count(result) == 0
} 


test_invalid {
  result = deny with input as data.mock.invalid
  result == message
}
