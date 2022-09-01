package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}


## Rule: Mandatory claims
## https://www.rfc-editor.org/rfc/rfc6749#section-5.1
mandatory_oauth2_claims := { "access_token" , "token_type" }

deny_mandatory_oauth2_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_oauth2_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}

## Rule: Optional claims
##  https://www.rfc-editor.org/rfc/rfc6749#section-5.1
## TODO:  "expires_in"
optional_oauth2_claims := {"refresh_token" , "scope"}

warn_optional_oauth2_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := optional_oauth2_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing some optional claims %v", [not_present_claims])
}


## Rule: Mandatory claims
## https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
mandatory_oidc_claims := { "id_token"  }

deny_mandatory_odic_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_oidc_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}

## Rule: Optional claims

optional_oidc_claims := {"nonce" }

warn_optional_oidc_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := optional_oidc_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing some optional claims %v", [not_present_claims])
}
