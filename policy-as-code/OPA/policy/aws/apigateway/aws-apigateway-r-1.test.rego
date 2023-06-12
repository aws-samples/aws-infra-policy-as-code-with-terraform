package aws.apigateway.r1

message = {"AWS-API-GATEWAY-R-1: AWS_IAM or CUSTOM Authorization should be set for resource 'aws_api_gateway_method.apigw_method'"}

test_valid {
  result = deny with input as data.mock.valid
  count(result) == 0
} 

test_invalid_none {
  result = deny with input as data.mock.invalid_none
  result == message
}

test_invalid_cognito {
  result = deny with input as data.mock.invalid_cognito
  result == message
}

test_valid_custom {
  result = deny with input as data.mock.valid_custom
  count(result) == 0
}
