package aws.apigateway.m4

message_log_level_invalid = {"AWS-API-GATEWAY-M-4: logging_level under aws_api_gateway_method_settings should not be OFF 'aws_api_gateway_method_settings.method_all'"}
message_log_level_undefined = {"AWS-API-GATEWAY-M-4:logging_level is not defined in aws_api_gateway_method_settings. Set logging_level as INFO or ERROR 'aws_api_gateway_method_settings.method_all'"}
message_method_setting_undefined = {"AWS-API-GATEWAY-M-4: If aws_api_gateway_stage is created then aws_api_gateway_method_settings must be used with logging_level set to either INFO or ERROR 'aws_api_gateway_stage.sample_stage'"}

test_valid_log_level {
  result = deny with input as data.mock.valid_log_level
  count(result) == 0
} 

test_log_level_invalid {
  result = deny with input as data.mock.invalid_log_level
  result == message_log_level_invalid
}

test_log_level_undefined {
  result = deny with input as data.mock.undefined_log_level
  result == message_log_level_undefined
}

test_method_setting_undefined {
  result = deny with input as data.mock.undefined_method_settings
  result == message_method_setting_undefined
}