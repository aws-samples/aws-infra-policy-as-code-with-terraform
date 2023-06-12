package aws.mwaa.m1

# Use secrets manager to store secrets used by DAGs

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mwaa_environment#airflow_configuration_options

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-env-variables.html#configuring-env-variables-customizing

# External links for Configuration options
# https://airflow.apache.org/docs/apache-airflow/2.2.2/configurations-ref.html#secrets
# https://airflow.apache.org/docs/apache-airflow-providers-amazon/stable/secrets-backends/aws-secrets-manager.html

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_mwaa_environment"
}

is_airflow_configuration_secrets_defined(resource){
    resource.change.after["airflow_configuration_options"]["secrets.backend"] == "airflow.providers.amazon.aws.secrets.secrets.secrets_manager.SecretsManagerBackend"
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not is_airflow_configuration_secrets_defined(resource)
    reason := sprintf("AWS-MWAA-M-1: MWAA environment '%s' must use secrets manager to store secrets. Configure 'airflow_configuration_options' to use \"secrets.backend\"=\"airflow.providers.amazon.aws.secrets.secrets.secrets_manager.SecretsManagerBackend\"." , [resource.address])
}
