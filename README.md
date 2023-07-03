[![Coverage Check](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform/actions/workflows/coverage.yaml/badge.svg)](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform/actions/workflows/coverage.yaml)

# Policy-as-Code

This repo contains Open Policy Agent (OPA) policies to test AWS infrastructure against terraform plan.

# Why OPA?

OPA provides a powerful policy engine that helps organizations enforce fine-grained policies across their applications and infrastructure, improving security, compliance, and policy management capabilities.

# Benefits of using this repo policies:

Implementing OPA-based preventive security controls for Terraform Infrastructure as Code (IaC) can establish a security baseline and safeguard resources before deployment into the AWS Accounts and reduce security risks.

# Introduction

What is OPA?

The OPA is an open source, general-purpose policy engine that unifies policy enforcement across the stack. 
OPA provides a high-level declarative language that lets you specify policy as code and simple APIs to offload policy decision-making from your software.

To learn more, refer 
* [OPA docs](https://www.openpolicyagent.org/docs/latest/)
* [OPA training](https://academy.styra.com/courses/opa-rego)

# Folder structure
* **policy-as-code/OPA/policy/aws/<service_name>** - contains the actual policy files written in rego language for each AWS service.
* **policy-as-code/OPA/policy/template** - contains the sample files for each OPA rule for AWS service.
* **policy-as-code/OPA/policy/common.utils.rego** - utils package for common code/functions used in actual rule rego files.

### Template folder files
1. **aws-service_name-policy_id.mock.json**: 
  Terraform mock policy file, that will be used for checking rego code. i.e. `./policy/aws/efs/aws-efs-m-2.mock.json`

2. **aws-service_name-policy_id.rego**:
    Rego policy file i.e. `./policy/aws/efs/aws-efs-m-2.rego`
3. **aws-service_name-policy_id.test.rego**
    Rego tests file. Valid cases & invalid cases i.e. `./policy/aws/efs/aws-efs-m-2.test.rego`

File naming convention: 

"aws-<service_name>-<type_of_control>-<policy_id>"

 - service_name - any of the AWS services E.g., s3, efs, dynamodb, etc.  - aws-s3-<type_of_control>-<policy_id>
 - type_of_control - can be any one of (m, r) - `m` refers to mandatory control, `r` for recommended control - aws-s3-m-<policy_id>
 - policy_id - can be a number E.g., 1, 2, 3  - aws-s3-m-1 or aws-s3-r-1

# Usage

## Pre-requisites:
1. Install [terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
2. Install [opa](https://www.openpolicyagent.org/docs/latest/#running-opa)
3. Install [conftest](https://github.com/open-policy-agent/conftest)

Download the repo and do the following:

1. Write your own terraform code and generate plan using below commands:
   ```
   terraform init 
   terraform plan -input=false -refresh -no-color -out=/tmp/planfile 
   terraform show -json /tmp/planfile > /tmp/plan.json

   ```
2. Run specific OPA rule against the generated terraform plan use:

   Go to the directory of the repo - `~/policy-as-code/OPA/policy ` (Note: check the path correctly)
   ``` 
   opa eval -i <terraform_plan_json_file_path> -d <OPA_rule_rego_file_path> -d <common_utils_file_path> "data.aws.<service_name>.<policy_id>.deny"
   ```
    E.g.
    ```
    cd ~/policy-as-code/OPA/policy
    opa eval -i /tmp/plan.json -d aws/efs/aws-efs-m-1.rego -d common.utils.rego "data.aws.efs.m2.deny"
    ```

3. Run all OPA rules in this repository against the generated terraform plan use:
   
    Go to the directory of the repo - `~/policy-as-code/OPA/` (Note: check the path correctly)
    ```
    conftest test  <terraform_plan_json_file_path> -o table --all-namespaces -p <OPA_rule_policy_dir_file_path>
    ```
     E.g.
     ```
     cd ~/policy-as-code/OPA/
     conftest test /tmp/tfplan.json -o table --all-namespaces -p policy/
     ```
   
4. If opa evaluations are done successfully against the generated plan, you can safely deploy the infrastructure. If not, modify terraform code to comply with the policies defined.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

