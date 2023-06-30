package utils

test_is_create_or_update {
	data.utils.is_create_or_update(["create"])
	data.utils.is_create_or_update(["delete", "create"])
	not data.utils.is_create_or_update(["create", "delete"])
	data.utils.is_create_or_update(["update"])
}

test_is_resource_create_or_update {
	data.utils.is_resource_create_or_update({"change": {"actions": ["create"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["delete", "create"]}})
	not data.utils.is_resource_create_or_update({"change": {"actions": ["create", "delete"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["update"]}})
}

test_compact {
	array = [
		"a",
		false,
		null,
		0,
		[],
		{},
	]

	["a"] == compact(array)
	[] == compact([false])
}

test_to_path {
	["a", "b", "c"] == to_path("a.b.c")
	["a", 123, "c"] == to_path("a.[123].c")
}

test_is_null_or_false {
	is_null_or_false(null) == true
	is_null_or_false(false) == true
	is_null_or_false(true) == false
	is_null_or_false("sample") == false
	is_null_or_false(["1", "2"]) == false
}

test_get {
	obj = {"a": {"b": [0, 1, {"c": "valid"}, {"d": false}]}}

	"valid" == get(obj, "a.b.[2].c")
	"valid" == get(obj, "a.b.[2].c")

	not get(obj, "a.b.[0].foo.bar")
}

test_get_or_default {
	obj = {"a": {"b": [0, 1, {"c": "valid"}, {"d": false}]}}

	"valid" == get_or_default(obj, "a.b.[2].c", false)
	false == get_or_default(obj, "a.b.[3].d", false)
	"does not exist" == get_or_default(obj, "a.b.[123].c", "does not exist")
	"does not exist" == get_or_default(obj, "a.b.[0].foo.bar", "does not exist")
}

test_has {
	obj = {"a": {"b": [0, 1, {"c": true}, {"d": false}]}}
	has(obj, "a.b.[2].c") == true
	has(obj, "a.b.[3].d") == true
	has(obj, "a.b.[123].c") == false
	has(obj, "a.b.[2].d") == false
}

test_keys {
	obj = {"a": 1, "b": 2, "c": 3, "d": {"e": 4}}
	arr = ["a", "b", "c", "d"]
	keys(obj) == {"a", "b", "c", "d"}
	keys(arr) == {0, 1, 2, 3}
}

test_is_fraction {
	obj = {"a": 2, "b": 3, "c": false, "d": "hello", "e": {"hello": "world"}}

	is_fraction(obj, {"a": 2})
	is_fraction(obj, {"a": 2, "b": 3})
	is_fraction(obj, {"a": 2, "c": false})
	is_fraction(obj, {"a": 2, "c": true}) == false
	is_fraction(obj, {"e": {"hello": "world"}})
	is_fraction(obj, {"e": {}}) == false
}

test_every {
	every([true, true, true], true) == true
	every([false, false, false], false) == true
	every([true, false, true], true) == false
	every([false, true, false], false) == false
	every([1, 1, 1], 1) == true
	every([1, 2, 3], 1) == false
	every([null, null], null) == true
	every(["", ""], "") == true
}

test_includes {
	includes(["a", "b", "c"], "b") == true
	includes([2, 3, 4, 5], 4) == true
	includes(["a", null, "c"], null) == true
	includes(["a", false, 3], false) == true
	includes(["a", false, 3], true) == false
}

test_size {
	size([]) == 0
	size([1, 2, 3]) == 3
	size([1, 2, 3, 4, 5]) == 5
	size([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) == 10
	size({"a": 0, "b": 1, "c": 2}) == 3
	size("hello") == 5
}

test_to_set {
	{"a", "b"} == to_set(["a", "b", "b", "a"])
	{"a", "b", null} == to_set(["a", "b", "b", null])
	{1, false, null} == to_set([1, 1, false, null, false])
}

test_to_array {
	["a", "b"] == to_array({"a", "b"})
	["a", "b"] == to_array({"b", "a"})
	[null, "a", "b"] == to_array({"a", "b", null})
	[null, false, 1] == to_array({1, false, null})
	[null, false, true, 1, "a", "z", {}] == to_array({1, true, false, null, "a", {}, "z"})
}

test_index_of {
	index_of(["a", 1, {}, false, null], "a") == 0
	index_of(["a", 1, {}, false, null], 1) == 1
	index_of(["a", 1, {}, false, null], {}) == 2
	index_of(["a", 1, {}, false, null], false) == 3
	index_of(["a", 1, {}, false, null], null) == 4
	index_of(["a", 1, {}, false, null], "nop") == -1
}

test_index_by {
	array := [{"a": 1, "b": 2}, {"a": 3, "b": 4}, {"a": 5, "b": 6}]
	index_by(array, {"a": 1}) == 0
	index_by(array, {"a": 3}) == 1
	index_by(array, {"b": 6}) == 2
	index_by(array, {"b": 3}) == -1
}

test_try_to_number {
	try_to_number("1") == 1
	try_to_number("1.2") == 1.2
	try_to_number("1.2.3") == "1.2.3"
	try_to_number("test") == "test"
}

test_find_service_resource {
    plan = {
        "resource_changes": [
            {
                "address": "aws_secretsmanager_secret.example",
				"mode": "managed",
                "type": "aws_secretsmanager_secret",
                "change": {
					"actions": [
						"create"
					]
                }
            },
			{
                "address": "aws_kms_key.example",
				"mode": "managed",
                "type": "aws_kms_key",
                "change": {
					"actions": [
						"delete"
					]
                }
            }
        ]
    }
    
	data.utils.find_service_resource(plan, "aws_secretsmanager") == ["aws_secretsmanager_secret.example"]
    count(data.utils.find_service_resource(plan, "aws_s3")) == 0
	count(data.utils.find_service_resource(plan, "aws_kms")) == 0
}

test_is_array_null_or_empty {
	is_array_null_or_empty([]) == true
	is_array_null_or_empty(null) == true
	is_array_null_or_empty(["1"]) == false
	is_array_null_or_empty(["1", "2"]) == false
}

test_contains_element {
	contains_element(["1", "2"], "1") == true
	contains_element(["1", "2"], "3") == false
	contains_element([], "1") == false
}

test_find_configuration_resource {
	# case 0 module
	plan0 = {
	      "resource_changes": [
		{
		  "address": "aws_ssm_parameter.ssm_compliant_referenced",
		  "mode": "managed",
		  "type": "aws_ssm_parameter",
		  "name": "ssm_compliant_referenced",
		  "provider_name": "registry.terraform.io/hashicorp/aws",
		  "change": { "actions": [ "create" ] }
		}
	      ],
	      "configuration": {
		"root_module": {
		  "resources": [
		    {
		      "address": "aws_ssm_parameter.ssm_compliant_referenced",
		      "type": "aws_ssm_parameter",
		      "name": "ssm_compliant_referenced"
		    }
		  ]
		}
	      }
	}
	data.utils.find_configuration_resource(plan0, plan0.resource_changes[0]) == plan0.configuration.root_module.resources[0]
	# case 1 module
	plan1 = {
	      "resource_changes": [
		{
		  "address": "module.testmodule.aws_ssm_parameter.ssm_compliant_referenced",
		  "module_address": "module.testmodule",
		  "mode": "managed",
		  "type": "aws_ssm_parameter",
		  "name": "ssm_compliant_referenced",
		  "provider_name": "registry.terraform.io/hashicorp/aws",
		  "change": { "actions": [ "create" ] }
		}
	      ],
	      "configuration": {
		"root_module": {
		  "module_calls": {
		    "testmodule": {
		      "module": {
			"resources": [
			  {
			    "address": "aws_ssm_parameter.ssm_compliant_referenced",
			    "type": "aws_ssm_parameter",
			    "name": "ssm_compliant_referenced"
			  }
			]
		      }
		    }
		  }
		}
	      }
	}
	data.utils.find_configuration_resource(plan1, plan1.resource_changes[0]) == plan1.configuration.root_module.module_calls.testmodule.module.resources[0]

	# case nested modules
	plan2 = {
	  "resource_changes": [
	    {
	      "address": "module.level1.aws_iam_role.role",
	      "module_address": "module.level1",
	      "type": "aws_iam_role",
	      "name": "role",
	      "change": { "actions": [ "create" ] }
	    },
	    {
	      "address": "module.level1.module.level2.aws_iam_policy.policy",
	      "module_address": "module.level1.module.level2",
	      "type": "aws_iam_policy",
	      "name": "policy",
	      "change": { "actions": [ "create" ] }
	    },
	    {
	      "address": "module.level1.module.level2.aws_iam_role_policy_attachment.this",
	      "module_address": "module.level1.module.level2",
	      "type": "aws_iam_role_policy_attachment",
	      "name": "this",
	      "change": { "actions": [ "create" ] }
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "module_calls": {
			"level1": {
			  "module": {
			    "resources": [
			      {
					"address": "aws_iam_role.role",
					"type": "aws_iam_role",
					"name": "role"
			      }
			    ],
			    "module_calls": {
			      "level2": {
					"module": {
					  "resources": [
					    {
					      "address": "aws_iam_policy.policy",
					      "type": "aws_iam_policy",
					      "name": "policy"
					    },
					    {
					      "address": "aws_iam_role_policy_attachment.this",
					      "type": "aws_iam_role_policy_attachment",
					      "name": "this"
					    }
					  ]
					}
			      }
			    }
			  }
			}
	      }
	    }
	  }
	}
	data.utils.find_configuration_resource(plan2, plan2.resource_changes[1]) == plan2.configuration.root_module.module_calls.level1.module.module_calls.level2.module.resources[0]

}
