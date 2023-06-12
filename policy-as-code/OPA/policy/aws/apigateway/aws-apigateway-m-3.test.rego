package aws.apigateway.m3

message = {"aws-apigw-m-3: Protocol provided in URL for HTTP backend integration should be set to https 'aws_api_gateway_integration.MyDemoIntegration'"}    
message_with_body = {"aws-apigw-m-3: Protocol provided in URL in body json for HTTP backend should be set to https 'aws_api_gateway_rest_api.sample_rest_api'"}

test_valid_protocol {
  result = deny with input as data.mock.valid_protocol
  count(result) == 0
} 

test_valid_body_protocol {
  result = deny with input as data.mock.valid_body_protocol
  count(result) == 0
} 

test_invalid_protocol {
  result = deny with input as data.mock.invalid_protocol
  result == message
}

test_invalid_body_protocol {
  result = deny with input as data.mock.invalid_body_protocol
  result == message_with_body
}
