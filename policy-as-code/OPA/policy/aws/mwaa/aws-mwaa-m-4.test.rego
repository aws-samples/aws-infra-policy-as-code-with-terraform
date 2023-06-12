package aws.mwaa.m4

msg := {"AWS-MWAA-M-4: MWAA environment 'aws_mwaa_environment.example' must use Cloudwatch for monitoring all MWAA events (dag_processing_logs, scheduler_logs, task_logs, webserver_logs, worker_logs). Enable all logs using 'logging_configuration'."}

test_mwaa_env_compliant {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_mwaa_env_defaults {
    result = deny with input as data.mock.mwaa_env_default
    result == msg
}

test_mwaa_env_invalid_dag {
    result = deny with input as data.mock.invalid_dag
    result == msg
}

test_mwaa_env_undefined_webserver {
    result = deny with input as data.mock.undefined_webserver
    result == msg
}
