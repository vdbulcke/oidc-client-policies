package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}


## Rule: Mandatory claims
## https://www.rfc-editor.org/rfc/rfc7662#section-2.2
mandatory_claims := { "active" }

deny_mandatory_oauth2_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}

deny_active_format[msg] {
    not is_boolean(input.active)
    msg := sprintf("Wrong active format should be boolean, got %v", [type_name(input.active)])
}



## Rule: Optional claims
## https://www.rfc-editor.org/rfc/rfc7662#section-2.2
optional_claims := {"scope" ,"client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti"}

warn_optional_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := optional_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing some optional claims %v", [not_present_claims])
}

warn_scope_format[msg] {
    not is_string(input.scope)
    msg := sprintf("Wrong scope format should be streing, got %v", [type_name(input.scope)])
}