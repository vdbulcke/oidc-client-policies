package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}


## Rule: Mandatory claims
## https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
mandatory_claims := { "sub" }

deny_mandatory_claims[msg] {

    ## get intersection between mandatory_claims and present_claims
    not_present_claims := mandatory_claims - present_claims

    ##  if mandatory claims not present
    not count(not_present_claims) == 0

    msg := sprintf("Missing some Mandatory claims %v", [not_present_claims])
}
