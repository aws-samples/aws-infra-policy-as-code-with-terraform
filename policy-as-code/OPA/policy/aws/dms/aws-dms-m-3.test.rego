package aws.dms.m3

test_valid {
	result = deny with input as data.mock.valid
	count(result) == 0
}

test_invalid {
	results = deny with input as data.mock.invalid
	count(results) == 6
	endpoints := [
		"aws_dms_endpoint.aurora_none",
		"aws_dms_endpoint.aurora_ssl_empy",
		"aws_dms_endpoint.azuredb_ssl_empy",
		"aws_dms_endpoint.oracle_ssl_none",
		"aws_dms_endpoint.sqlserver_ssl_none",
		"aws_dms_endpoint.sqlserver_ssl_null",
	]

	messages := {x | x := sprintf("AWS-DMS-M-3: DMS endpoint '%s' must be set to use a secure channel for database migration", [endpoints[_]])}
	messages == results
}
