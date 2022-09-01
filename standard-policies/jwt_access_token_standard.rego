package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}


## Rule: Mandatory claims
## https://datatracker.ietf.org/doc/html/rfc9068#section-2.2
## https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3
mandatory_claims := { "sub" , "iss", "aud", "iat", "exp", "jti", "client_id", "scope" }

deny_mandatory_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}

## Rule: Scope format 
## https://www.rfc-editor.org/rfc/rfc6749#section-3.3

deny_scope_format[msg] {

   
    not is_string(input.scope)
    msg := sprintf("Wrong scope format should be string, got %v", [type_name(input.scope)])
}



## Rule: Optional claims
## https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.1
optional_claims := {"auth_time" ,"acr", "amr"}

warn_optional_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := optional_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing some optional claims %v", [not_present_claims])
}
