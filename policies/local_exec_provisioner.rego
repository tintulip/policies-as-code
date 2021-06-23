package rules.local_exec_provisioner

import data.fugue

resource_type = "MULTIPLE"

contains_local_exec(resource) {
	provisioners = resource.provisioners[_]
	resource.provisioners != []
	provisioners.type == "local-exec"
}

policy[p] {
	[_, value] := walk(input._plan.configuration.root_module)
	resource_ids := input.resources[_].id
	check_resource := value.resources[_]
	not contains_local_exec(check_resource)
	resource_address := [ i | i = resource_ids; endswith(i, check_resource.address) ]
	resource = input.resources[resource_address[_]]
	p = fugue.allow_resource(resource)
}
policy[p] {
	[_, value] := walk(input._plan.configuration.root_module)
	resource_ids := input.resources[_].id
	check_resource := value.resources[_]
	contains_local_exec(check_resource)
	resource_address := [ i | i = resource_ids; endswith(i, check_resource.address) ]
	resource = input.resources[resource_address[_]]
	p = fugue.deny_resource_with_message(resource, "This resource is not allowed to contain a local-exec provisioner")
}