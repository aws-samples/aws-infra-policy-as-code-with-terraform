Amazon EKS Blueprint for Terraform contains a collection of Amazon EKS cluster patterns implemented in Terraform that demonstrates how fast and easy it is for customers to adopt Amazon EKS. The Open Policy Agent is an open-source, general purpose policy engine that unifies policy enforcement across the stack. Using Open Policy Agent (OPA) to scan your infrastructure as code and within your Kubernetes cluster is a smart and effective way to ensure the security and compliance of your environment. <br/>
This repo contains below OPA Rego policies for the EKS Blueprint for Terraform project:

1. eks-blueprint-control-logs: Check if the EKS control plane has valid logs enabled.
2. eks-blueprint-private-endpoint: Check if the EKS cluster uses private endpoints
3. eks-blueprint-security-group: Check if the EKS Cluster has security group defined
4. eks-blueprint-selfmanaged-security-group: Check if self managed cluster nodes have security groups defined
5. eks-blueprint-disk-size: Check if the EKS Cluster node groups have disk_size parameter configured

# Pre-requisites

- [Install AWS CLI version 2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) on your local machine
- [Install Open Policy Agent](https://github.com/open-policy-agent/opa) from the latest release
- [Install Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)

# Evaluate EKS Blueprint for Terraform plan with OPA

You can git clone the two repos, one containing the EKS Blueprint terraform configuration and this one containing the OPA Rego policies which would be used to scan the terraform plans
```
   git clone https://github.com/aws-ia/terraform-aws-eks-blueprints.git
   git clone https://github.com/gpmattoo/aws-infra-policy-as-code-with-terraform.git
```

You can initialize and run the terraform plan command 
```
terraform -chdir=terraform-aws-eks-blueprints/patterns/fargate-serverless/ init
terraform -chdir=terraform-aws-eks-blueprints/patterns/fargate-serverless/ plan --out tfplan.binary
terraform -chdir=terraform-aws-eks-blueprints/patterns/fargate-serverless/ show -json tfplan.binary > tfplan.json

cat tfplan.json
```

Here is the OPA policy execution to evaluate the terraform plan from fargate-serverless pattern of EKS Blueprint

```
opa eval -i /Users/gpmattoo/devOpsRepos/aws-infra-policy-as-code-with-terraform/policy-as-code/OPA/policy/aws/blueprints/eks/fargate-serverless-tfplan.json -d /Users/gpmattoo/devOpsRepos/aws-infra-policy-as-code-with-terraform/policy-as-code/OPA/policy/aws/blueprints/eks/eks-blueprint-control-logs.rego -d common.utils.rego "data.aws.blueprints.eks.controllogs.deny"
```
and here is the output of above policy execution:
```
{
  "result": [
    {
      "expressions": [
        {
          "value": [],
          "text": "data.aws.blueprints.eks.controllogs.deny",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
```

# Testing EKS Blueprint OPA Rego Policies
```
   opa test <path_to_opa_control> <path_to_common_utils.rego> -v
```
For instance:
```
   cd ~/aws-infra-policy-as-code-with-terraform/policy-as-code/OPA/policy/aws/blueprints/eks
   opa test eks-blueprint-control-logs* common.utils.rego -v
```

# EKS Blueprint OPA Rego Test Coverage
```
   opa test <path_to_opa_control> <path_to_common_utils.rego> -v --coverage
```
For instance:
```
   cd ~/aws-infra-policy-as-code-with-terraform/policy-as-code/OPA/policy/aws/blueprints/eks
   opa test eks-blueprint-control-logs* common.utils.rego -v --coverage
```