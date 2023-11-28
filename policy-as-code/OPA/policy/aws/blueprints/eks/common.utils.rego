package utils

# Checks if action is create or update
# Common path: resource.change.actions
is_create_or_update(change_actions) {
	change_actions[count(change_actions) - 1] == ["create", "update"][_]
}

# Checks of resource is being created or updated
is_resource_create_or_update(resource) {
	is_create_or_update(resource.change.actions)
}

# Creates an array with all falsey values removed.
# The values false, null, 0, "", {} and [] are considered falsey.
compact(array) = output {
	output := [value |
		value := array[_]
		not is_null(value)
		not value == false
		not value == ""
		not value == 0
		not value == []
		not value == {}
	]
}

# Checks if `match` value matches to all items in array.
every(array, match) {
	count([value |
		value := array[_]
		value == match
	]) == count(array)
} else = false {
	true
}

#  Gets the value at path of object.
get(object, path) = output {
	[obj_path, value] = walk(object)
	path_array := to_path(path)
	obj_path == path_array
	output := value
}

# Gets the value at path of object.
# If the resolved value is undefined,
# the default_value is returned in its place.
get_or_default(object, path, default_value) = output {
	output := get(object, path)
} else = output {
	output := default_value
}

# Checks if path exists on object
has(object, path) {
	[obj_path, value] = walk(object)
	obj_path == to_path(path)
} else = false {
	true
}

# Checks if value exists in array
includes(array, value) {
	value == array[_]
} else = false {
	true
}

# Gets index of object in array that matches provided fraction object
index_by(array, fraction) = output {
	some i
	item = array[i]
	is_fraction(item, fraction)
	output := i
} else = output {
	output := -1
}

# Gets index of value in array
index_of(array, value) = output {
	some i
	item = array[i]
	item == value
	output := i
} else = output {
	output := -1
}

# Checks if value is null or false
is_null_or_false(value) {
	is_null(value)
} else {
	value == false
} else = false {
    true
}

# Checks if object matches fraction
is_fraction(object, fraction) {
	search_keys = keys(fraction)
	count({key |
		key = search_keys[_]
		object[key] == fraction[key]
	}) == count(search_keys)
} else = false {
	true
}

# Gets the keys of object
keys(object) = output {
	output := {key |
		[path, value] = walk(object)
		key := path[0]
	}
}

# Gets the size of collection
size(collection) = output {
	is_string(collection)
	output := count(collection)
} else = output {
	output := count(keys(collection))
}

# Converts set to an array
to_array(set) = output {
	output := [value |
		value := set[_]
	]
}

# Converts array to a set
to_set(array) = output {
	output := {value |
		value := array[_]
	}
}

_parse_array_index(value) = output {
	contains(value, "[")
	number_string := substring(value, 1, count(value) - 2)
	output = try_to_number(number_string)
} else = output {
	output = value
}

# Converts string path to a path array
to_path(path) = output_array {
	output_array := [value |
		part := split(path, ".")[_]
		value := _parse_array_index(part)
	]
}

# Attempts to converts string to a number
try_to_number(string) = out {
	out := to_number(string)
} else = out {
	out := string
}

is_resource_of_type(resource, service) {
	resource.mode == "managed"
    contains(resource.type, service)
    resource.change.actions[count(resource.change.actions) - 1] != "delete"
}

# Checks if service resource exists in the plan
find_service_resource(plan, service) = result {
	result := [ x.address | x := plan.resource_changes[_]; is_resource_of_type(x, service)]
}

# Checks if arrays is null or empty
is_array_null_or_empty(value) {
	is_null(value)
} else {
	size(value) = 0
} else = false {
    true
}

# Check if an array contains specified value
contains_element(array, value) {
	array[_] = value
} else = false {
	true
}

# find configuration entries for resource
find_configuration_resource(plan, resource) = cfgresource{
	# case where there is no module
	not resource.module_address
	some ssm_resource
	plan.configuration.root_module.resources[ssm_resource].address == resource.address
	cfgresource := plan.configuration.root_module.resources[ssm_resource]
} else = cfgresource{
	some ssm_resource
	# case with module (or nested modules)
	base_path := "configuration.root_module"
	# get module_address and split with "."
	module_address_list :=  split(resource.module_address, ".")
	# list comprehention to keep only modules names not "module." entries
	nested_module_path := [ path | module_address_list[i] != "module"; path :=  module_address_list[i] ]
	# rebuild path for configuration section
	temp_path := concat(".", [ path2 | nested_module_path[i] ; path2 := sprintf("module_calls.%s.module",[nested_module_path[i]])])
	temp_path2 := concat(".", [base_path, temp_path])

	# search input object starting at root_module
	myobj := data.utils.get(plan, temp_path2)
	concat(".", [resource.module_address, myobj.resources[ssm_resource].address]) == resource.address
	cfgresource := myobj.resources[ssm_resource]
}