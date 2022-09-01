package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}


## Rule: Mandatory claims
## https://openid.net/specs/openid-connect-core-1_0.html#IDToken
mandatory_claims := { "sub" , "iss", "aud", "iat", "exp" }

deny_mandatory_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}

## Rule: Optional claims
## https://openid.net/specs/openid-connect-core-1_0.html#IDToken
optional_claims := {"auth_time" , "nonce", "acr", "amr", "azp"}

warn_optional_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := optional_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing some optional claims %v", [not_present_claims])
}

