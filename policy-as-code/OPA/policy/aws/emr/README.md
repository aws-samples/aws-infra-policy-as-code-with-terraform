Following EMR Controls are implemented:

1. aws-emr-m-1: Ensure data gathered and accessed by EMRL cluster is over TLS protected channel
2. aws-emr-m-2: Ensure that EMR should have VPC endpoint to prevent network traffic leaving from the AWS network.
3. aws-emr-m-3: Ensure that EMR Cluster logs should be collected in dedicated S3 bucket.
4. aws-emr-m-4: Ensures usages of custom security groups for EMR cluster
5. aws-emr-m-5: Ensure that EMR Cluster EC2 instances must be hardened to CIS level 1
