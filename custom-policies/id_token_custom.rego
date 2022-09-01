package main

import future.keywords
## Helpers
## extract all claims as a set
present_claims := { c |
    ## every key 'c' in input
    input[c]
}

## Rule: Custom claims
## TODO: add your custom mandatory caims here
custom_claims := {"given_name" , "name", "family_name", "email", "preferred_username", "foo"}

deny_custom_claims[msg] {

     ## get intersection between optional claims and present_claims
    not_present_claims := custom_claims - present_claims
     ## get intersection between optional claims and present_claims
    not count(not_present_claims) == 0

    msg := sprintf("Missing custom claims %v", [not_present_claims])
}


## Rule: Example key value check
### "foo": "bar"
deny_custom_claims[msg] {
    key := "foo"
    value := "bar"

    input[key] != value
    msg := sprintf("Claim %v not maching, expeced %v got %v", [key, value, input[key]])
}

