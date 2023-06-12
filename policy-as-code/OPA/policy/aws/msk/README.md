Following MSK Controls are implemented:

1. aws-msk-m1: Ensure data gathered and accessed by AWS MSK cluster is over TLS protected channel
2. aws-msk-m2: Enable server side encryption using customer managed key (CMK) and not the default AWS CMK
3. aws-msk-m3: AWS MSK Kafka version should be above 2.5.1 to ensure Zookeeper encryption
4. aws-msk-m4: AWS MSK Authentication should be set to IAM