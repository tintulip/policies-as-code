package fugue.regula.config

# FIXME: Eventually remove these waivers as they are overpermissive
waivers[waiver] {
    waiver := {
        "rule_name": "iam_permissive_attached_policy"
    }
} {
    waiver := {
        "rule_name": "iam_service_star"
    }
} {
    waiver := {
        "rule_name": "vpc_igw_creation_block"
    }
} {
    waiver := {
        "rule_name": "alb_ssl_configuration"
    }
}