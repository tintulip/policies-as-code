package rules.local_exec_provisioner

import data.fugue

resource_type = "MULTIPLE"

contains_local_exec(resource) {
	provisioners = resource.provisioners[_]
  resource.provisioners != []
	provisioners.type == "local-exec"
}

policy[p] {
	resource_config = input._plan.configuration.root_module.resources[_]
	not contains_local_exec(resource_config)
	resource = input.resources[resource_config.address]
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource_config = input._plan.configuration.root_module.resources[_]
	contains_local_exec(resource_config)
	resource = input.resources[resource_config.address]
	p = fugue.deny_resource_with_message(resource, "This resource is not allowed to contain a local-exec provisioner")
}

policy[p] {
	resource_config = input._plan.configuration.root_module.module_calls[_].module.resources[_]
	not contains_local_exec(resource_config)
	module_name := split(resource_config.provider_config_key, ":")[0]
	resource_address := sprintf("module.%s.%s", [module_name, resource_config.address])
	resource = input.resources[resource_config.address]
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource_config = input._plan.configuration.root_module.module_calls[_].module.resources[_]
	contains_local_exec(resource_config)
	module_name := split(resource_config.provider_config_key, ":")[0]
	resource_address := sprintf("module.%s.%s", [module_name, resource_config.address])
	resource = input.resources[resource_address]
	p = fugue.deny_resource_with_message(resource, "This resource is not allowed to contain a local-exec provisioner")
}