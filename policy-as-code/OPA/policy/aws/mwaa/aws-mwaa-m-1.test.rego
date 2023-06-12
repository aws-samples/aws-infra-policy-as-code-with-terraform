package aws.mwaa.m1

msg := {"AWS-MWAA-M-1: MWAA environment 'aws_mwaa_environment.valid' must use secrets manager to store secrets. Configure 'airflow_configuration_options' to use \"secrets.backend\"=\"airflow.providers.amazon.aws.secrets.secrets.secrets_manager.SecretsManagerBackend\"."}

test_mwaa_env_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_mwaa_env_defaults {
    result = deny with input as data.mock.mwaa_env_default
    result == msg
}

test_mwaa_env_invalid {
    result = deny with input as data.mock.invalid
    result == msg
}