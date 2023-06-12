package aws.mwaa.m3

no_endpoints_msg := {"AWS-MWAA-M-3: Resource 'aws_mwaa_environment.valid' is used and traffic should be restricted to MWAA from VPC endpoint using servicenames '[\"com.amazonaws.eu-central-1.s3\", \"com.amazonaws.eu-central-1.monitoring\", \"com.amazonaws.eu-central-1.ecr.dkr\", \"com.amazonaws.eu-central-1.ecr.api\", \"com.amazonaws.eu-central-1.logs\", \"com.amazonaws.eu-central-1.sqs\", \"com.amazonaws.eu-central-1.kms\", \"com.amazonaws.eu-central-1.airflow.api\", \"com.amazonaws.eu-central-1.airflow.env\", \"com.amazonaws.eu-central-1.airflow.ops\"]' (create MWAA related services VPC endpoints)."}
not_all_endpoints_msg := {"AWS-MWAA-M-3: Resource 'aws_mwaa_environment.valid' is used and traffic should be restricted to MWAA from VPC endpoint using servicenames '[\"com.amazonaws.eu-central-1.airflow.api\"]' (create MWAA related services VPC endpoints)."}

test_mwaa_env_valid_endpoints {
    result = deny with input as data.mock.all_endpoints
    count(result) == 0
}

test_mwaa_env_no_endpoints{
    result = deny with input as data.mock.no_endpoints
    result == no_endpoints_msg
}

test_mwaa_env_invalid {
    result = deny with input as data.mock.not_all_endpoints
    result == not_all_endpoints_msg
}
