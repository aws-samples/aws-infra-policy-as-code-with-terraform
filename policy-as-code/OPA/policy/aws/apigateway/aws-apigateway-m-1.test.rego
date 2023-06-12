package aws.apigateway.m1

message = {"AWS-API-GATEWAY-M-1: API Gateway resources should not be publicly accessible. Choose endpoint_configuration_types as PRIVATE 'aws_api_gateway_rest_api.apigw_restapi'"}

test_valid_endpoint_configuration_types {
  result = deny with input as data.mock.valid_endpoint_configuration_types
  count(result) == 0
} 

test_invalid_endpoint_configuration_types {
  result = deny with input as data.mock.invalid_endpoint_configuration_types
  result == message
}

