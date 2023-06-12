package aws.apigateway.m2

message_cache_undecalred = {"AWS-API-GATEWAY-M-2: If cache_cluster_enabled is set to true, then cache_data_encrypted must also be set to true. Set this parameter using aws_api_gateway_method_settings resource. 'aws_api_gateway_stage.sample_stage'"}
message_cache_unencrypted = {"AWS-API-GATEWAY-M-2: If cache_cluster_enabled is set to true then cache_data_encrypted must also be set to true. 'aws_api_gateway_stage.sample_stage'"}  

test_valid_cache_encrypted {
  result = deny with input as data.mock.valid_cache_encrypted
  count(result) == 0
} 

test_invalid_cache_unencrypted {
  result = deny with input as data.mock.invalid_cache_unencrypted
  result == message_cache_unencrypted
}

test_undefined_cache_not_decalred {
  result = deny with input as data.mock.undefined_cache_not_decalred
  result == message_cache_undecalred
}
