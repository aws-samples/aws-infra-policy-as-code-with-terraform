Following MWAA Controls are implemented:

1. aws-mwaa-m-1: Use secrets manager to store secrets used by DAGs
2. aws-mwaa-m-2: Ensure MWAA environment should be encrypted using customer managed keys (CMK)
3. aws-mwaa-m-3: Ensure VPC endpoint exists for MWAA to prevent traffic leaving from AWS network
4. aws-mwaa-m-4: Use Cloudwatch to log MWAA events
5. aws-mwaa-m-5: Ensure MWAA environment webserver Access mode has to be Private