package aws.emr.m2

test_valid_emr_cluster_valid_policy{
    result = deny with input as data.mock.emr_cluster_valid_endpoints
    count(result) == 0
}

test_no_cluster_valid_vpc_endpoints{
    result = deny with input as data.mock.no_cluster_valid_endpoints
    count(result) == 0
}

test_emr_cluster_no_eks_vpc_endpoint{
    result = deny with input as data.mock.emr_cluster_with_ec2_emr_endpoint
    msg := {"AWS-EMR-M-2: Resource 'aws_emrcontainers_virtual_cluster.emr_eks_cluster' is used and traffic should be restricted to EMR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.emr-containers' (create EMR EKS VPC endpoint)"}
    result == msg
}

test_emr_cluster_no_ec2_vpc_endpoint{
    result = deny with input as data.mock.emr_cluster_with_eks_endpoint
    msg = {"AWS-EMR-M-2: Resource 'aws_emr_cluster.cluster' is used and traffic should be restricted to EMR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.elasticmapreduce' (create EMR EC2 VPC endpoint)"}
    result == msg
}

test_emr_clusters_with_no_vpc_endpoints{
    result = deny with input as data.mock.emr_clusters_no_endpoints
    msg = {"AWS-EMR-M-2: Resource 'aws_emr_cluster.cluster' is used and traffic should be restricted to EMR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.elasticmapreduce' (create EMR EC2 VPC endpoint)",
            "AWS-EMR-M-2: Resource 'aws_emrcontainers_virtual_cluster.emr_eks_cluster' is used and traffic should be restricted to EMR from VPC endpoint using servicename 'com.amazonaws.eu-central-1.emr-containers' (create EMR EKS VPC endpoint)"}
    result == msg
}

test_no_cluster_vpc_endpoint_missing_policy{
    result = deny with input as data.mock.no_cluster_missing_endpoint_policy
    msg = {"AWS-EMR-M-2: VPC endpoint policy is not defined for 'aws_vpc_endpoint.emr_vpc_endpoint_with_missing_policy'.",
        "AWS-EMR-M-2: VPC endpoint policy is not defined for 'aws_vpc_endpoint.emr_eks_vpc_endpoint_with_missing_policy'."}
    result == msg
}

test_no_cluster_vpc_endpoint_with_invalid_policy{
    result = deny with input as data.mock.no_cluster_invalid_endpoint_policy
    msg = {"AWS-EMR-M-2: EMR vpc endpoint policy least privilege for resources is not used for 'aws_vpc_endpoint.emr_vpc_endpoint_with_invalid_policy'.",
        "AWS-EMR-M-2: EMR vpc endpoint policy least privilege for resources is not used for 'aws_vpc_endpoint.emr_eks_vpc_endpoint_with_invalid_policy'."}
    result == msg
}
