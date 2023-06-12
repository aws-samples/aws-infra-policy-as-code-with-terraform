Following ELASTICACHE Controls are implemented:

1. aws-elasticache-m-1: Ensure that Amazon ElastiCache service data must be encrypted in transit.
2. aws-elasticache-m-2: Ensure that Amazon ElastiCache service data are encrypted at rest using AWS CMK.
3. aws-elasticache-m-3: Ensure that Amazon ElastiCache service use Role-Based Access Control (RBAC) authentication instead of Redis AUTH
4. aws-elasticache-m-4: Ensure that AWS ElastiCache Log Configuration is configured to deliver log events to CloudWatch or Kinesis Data Firehose.
5. aws-elasticache-m-5: Ensure that Amazon ElastiCache cluster events are send to Amazon SNS.