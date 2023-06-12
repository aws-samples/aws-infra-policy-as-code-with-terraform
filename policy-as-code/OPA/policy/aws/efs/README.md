Following EFS Controls are implemented:

1. aws-efs-m-1: Ensure that Amazon EFS file systems are encrypted at rest using AWS KMS CMK.
2. aws-efs-m-2: Ensure that Amazon EFS mount target security groups are configured and not the default one.
3. aws-efs-m-3: Ensure that Amazon EFS file systems access policy is limited/restrictive and should not contain wildcard '*'.
4. aws-efs-r-1: Ensure that Amazon EFS file system access point uses app specific directory instead of systems root directory.