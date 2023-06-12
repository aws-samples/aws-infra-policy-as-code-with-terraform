package aws.utils

test_is_service_vpc_endpoint_exists {
    plan = {
        "resource_changes": [
            {
                "mode": "managed",
                "type": "aws_vpc_endpoint",
                "change": {
                    "after": {
                        "service_name": "com.amazonaws.eu-central-1.secretsmanager"
                    }
                }
            }
        ]
    }
    
	data.aws.utils.is_service_vpc_endpoint_exists(plan, "com.amazonaws.eu-central-1.secretsmanager")
    not data.aws.utils.is_service_vpc_endpoint_exists(plan, "com.amazonaws.eu-central-1.unknown")
}