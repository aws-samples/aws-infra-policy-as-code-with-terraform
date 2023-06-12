package aws.mwaa.m4

# Use Cloudwatch to log MWAA events

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mwaa_environment#logging-configurations

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/mwaa/latest/userguide/monitoring-airflow.html#monitoring-airflow-log-groups

valid_log_types = [
    "dag_processing_logs",
    "scheduler_logs",
    "task_logs",
    "webserver_logs",
    "worker_logs"
]

is_in_scope(resource) {
	resource.mode == "managed"
	data.utils.is_create_or_update(resource.change.actions)
	resource.type == "aws_mwaa_environment"
}

logs_enabled(array, log_type){
   array[_][log_type][_].enabled
} else = false{
    true
}

includes_all(resource, valid_log_types){
    array_target = resource.change.after.logging_configuration
    count([log_type |
        log_type := valid_log_types[_]
        logs_enabled(array_target, log_type)
    ]) == count(valid_log_types)
}else = false {
    true
}

deny[reason] {
    resource := input.resource_changes[_]
    is_in_scope(resource)

    not includes_all(resource, valid_log_types)
    reason := sprintf("AWS-MWAA-M-4: MWAA environment '%s' must use Cloudwatch for monitoring all MWAA events (dag_processing_logs, scheduler_logs, task_logs, webserver_logs, worker_logs). Enable all logs using 'logging_configuration'.", [resource.address])
}
