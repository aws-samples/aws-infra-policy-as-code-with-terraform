package aws.emr.m1

# Ensure data gathered and accessed by EMRL cluster is over TLS protected channel

# Terraform policy resource link
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_security_configuration

# AWS link to policy definition/explanation
# https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-create-security-configuration.html
# https://asecure.cloud/a/configure_emr_security_configuration/

get_error_message(security_configuration) = message {
	not security_configuration.EncryptionConfiguration.EnableInTransitEncryption
	message := "AWS-EMR-M-1: EMR security configuration '%s' must enable data encryption in transit"
} else = message {
	not security_configuration.EncryptionConfiguration.EnableAtRestEncryption
	message := "AWS-EMR-M-1: EMR security configuration '%s' must enable data encryption at rest"
} else = message {
	not security_configuration.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EnableEbsEncryption
	message := "AWS-EMR-M-1: EMR security configuration '%s' must enable EBS encryption at rest"
}

deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_emr_cluster"
	not value.expressions.security_configuration.references
	not value.expressions.security_configuration.constant_value
	reason := sprintf("AWS-EMR-M-1: EMR cluster '%s' must include reference to ERM security configuration", [value.address])
}

deny[reason] {
	[path, value] := walk(input.configuration.root_module)
	value.mode == "managed"
	value.type == "aws_emr_security_configuration"
	security_configuration = json.unmarshal(value.expressions.configuration.constant_value)
	error_message = get_error_message(security_configuration)
	error_message
	reason := sprintf(error_message, [value.address])
}
