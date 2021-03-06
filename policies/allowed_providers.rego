package rules.allowed_providers

import data.fugue

resource_type = "MULTIPLE"

allowlist = [
  "aws",
  "random"
]

is_allowed_provider(resource) {
	resource._provider == allowlist[_]
}

policy[p] {
  resource = input.resources[_]
  is_allowed_provider(resource)
  p = fugue.allow_resource(resource)
}

policy[p] {
  resource = input.resources[_]
  not is_allowed_provider(resource)
  p = fugue.deny_resource_with_message(resource, "This resource is not from an approved provider")
}