Following EC2 Controls are implemented:

1. aws-ec2linux-m-1: Ensure that EC2 instance has no public IP address associated
2. aws-ec2linux-m-2: Ensure that EC2 instance uses IMDSv2 metadata service version
3. aws-ec2linux-r-1: Ensure that EC2 instance has security group attached and this group doesn't contain 0.0.0.0/0 as inbound rule
