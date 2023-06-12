Following DMS Controls are implemented:

1. aws-dms-m-1: Ensure that the data managed by AWS Database Migration Service (DMS) replication instances is encrypted 
   with KMS Customer Master Keys (CMKs) instead of AWS managed-keys (default keys used by the DMS service 
   when there are no customer-managed keys defined).
2. aws-dms-m-2: Ensure the replication instance itself must not be publicly accessible.
3. aws-dms-m-3: Ensure use of secure channel for database migration.
4. aws-dms-m-4: Ensure that DMS should have VPC endpoint to prevent network traffic leaving from the AWS network.
5. aws-dms-m-5: Ensure that Amazon Database Migration Service (DMS) replication instances have the Auto Minor Version Upgrade feature enabled