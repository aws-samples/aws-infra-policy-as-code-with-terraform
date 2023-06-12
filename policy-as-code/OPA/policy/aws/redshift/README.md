Following REDSHIFT Controls are implemented:

1. aws-redshift-m-1: Ensure the AWS Redshift clusters are not be publicly accessible
2. aws-redshift-m-2: Ensure all user connections to Redshift clusters are encrypted by using "require_ssl" parameter
3. aws-redshift-m-3: Ensure the AWS Redshift clusters are encrypted at rest and a dedicated CMK is being used
4. aws-redshift-m-4: Ensure the AWS Redshift clusters have user activity logging enabled
5. aws-redshift-m-5: Ensure that 'awsuser' is not used as 'master_username' for database access.
6. aws-redshift-r-1: Ensure the AWS Redshift clusters are allowed version upgrades
7. aws-redshift-r-2:  Ensure the AWS Redshift clusters have automated snapshots enabled
