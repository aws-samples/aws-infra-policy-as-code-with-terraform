Amazon EKS Blueprint for Terraform contains a collection of Amazon EKS cluster patterns implemented in Terraform that demonstrates how fast and easy it is for customers to adopt Amazon EKS. The Open Policy Agent is an open-source, general purpose policy engine that unifies policy enforcement across the stack. Using Open Policy Agent (OPA) to scan your infrastructure as code and within your Kubernetes cluster is a smart and effective way to ensure the security and compliance of your environment. <br/>
This repo contains below OPA Rego policies for the Fargate Serverless pattern from the EKS Blueprint for Terraform project:

1. eks-blueprint-control-logs: Check if the EKS control plane has valid logs enabled.
2. eks-blueprint-private-endpoint: Check if the EKS cluster uses private endpoints
3. eks-blueprint-security-group: Check if the EKS Cluster has security group defined
4. eks-blueprint-selfmanaged-security-group: Check if self managed cluster nodes have security groups defined
5. eks-blueprint-disk-size: Check if the EKS Cluster node groups have disk_size parameter configured
