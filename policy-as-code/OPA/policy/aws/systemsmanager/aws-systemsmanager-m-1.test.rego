package aws.systemsmanager.m1

msg1 := {"AWS-SYSTEMSMANAGER-M-1: Parameter store security string parameter 'aws_ssm_parameter.ssm_not_compliant_default' should be configured with CMK."}
msg2 := {"AWS-SYSTEMSMANAGER-M-1: Parameter store security string parameter 'aws_ssm_parameter.ssm_not_compliant_hard_coded' should be configured with CMK."}
msg3 := {"AWS-SYSTEMSMANAGER-M-1: Only SecureString parameter type is allowed for Parameter store 'aws_ssm_parameter.ssm_not_compliant_string'."}
msg4 := {"AWS-SYSTEMSMANAGER-M-1: Only SecureString parameter type is allowed for Parameter store 'aws_ssm_parameter.ssm_not_compliant_stringList'."}

test_ssm_not_compliant_default {
  result = deny with input as data.mock.ssm_not_compliant_default
  result == msg1
}

test_ssm_not_compliant_hard_coded {
  result = deny with input as data.mock.ssm_not_compliant_hard_coded
  result == msg2
}

test_ssm_not_compliant_type_string {
  result = deny with input as data.mock.ssm_not_compliant_string
  result == msg3
}

test_ssm_not_compliant_type_string_list {
  result = deny with input as data.mock.ssm_not_compliant_stringList
  result == msg4
}

test_ssm_compliant_hard {
  result = deny with input as data.mock.ssm_compliant_hard
  count(result) == 0
}

test_ssm_compliant_referenced {
  result = deny with input as data.mock.ssm_compliant_referenced
  count(result) == 0
}

test_ssm_compliant_referenced_without_module {
  result = deny with input as data.mock.ssm_compliant_referenced_without_module
  count(result) == 0
}
