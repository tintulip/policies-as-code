package rules.iam_role_assumed_from_other_accounts

import data.fugue

resource_type = "MULTIPLE"

roles = fugue.resources("aws_iam_role")

is_invalid(resource) {
  assume_role_policy = json.unmarshal(resource.assume_role_policy)
  statements = as_array(assume_role_policy)
  statement := statements[_].Statement
  principal := statement[_].Principal
  not startswith(principal.AWS, "arn:aws:iam::620540024451:")
}

policy[p] {
	resource = roles[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = roles[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "Only the builder account is allowed to assume this role")
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else {
	x = true
}