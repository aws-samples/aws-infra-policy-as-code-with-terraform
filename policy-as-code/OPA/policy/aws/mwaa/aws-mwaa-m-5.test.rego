package aws.mwaa.m5

msg := {"AWS-MWAA-M-5: MWAA environment 'aws_mwaa_environment.example' webserver Access mode has to be Private (make sure 'webserver_access_mode' argument is set)."}

test_mwaa_env_valid {
    result = deny with input as data.mock.valid
    count(result) == 0
}

test_mwaa_env_defaults {
    result = deny with input as data.mock.mwaa_env_default
    count(result) == 0
}

test_mwaa_env_invalid {
    result = deny with input as data.mock.invalid
    result == msg
}
