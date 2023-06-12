Following ECR Controls are implemented:

1. aws-ecr-m-1: Ensure that the immutable tags force you to update the image tag on each push to the image repository.
2. aws-ecr-m-2: Access to ECR repository should be limited to user/services needed via either IAM or resource policy ('*' shouldn't be used in the access policy).
3. aws-ecr-m-3: Ensure that the ECR repository images scan on push is enabled on the central repo.
4. aws-ecr-m-4: Ensure VPC endpoint is created to prevent ECR network traffic leaving from the AWS network
5. aws-ecr-m-5: Ensure lifecycle policy for image repository to automatically remove untagged or old container images
6. aws-ecr-m-6: Ensure that VPC endpoint must have policy allowing only to company operated ECR repositories.