package main

import future.keywords

## WARNING: Input MUST be generated from this command
###
###     conftest parse --parser json output/id_token.json output/userinfo.json
### 


## Rule: Mandatory claims
## https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
## "The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token; " 
deny_userinfo_sub[msg] {

    not input["output/id_token.json"].sub == input["output/userinfo.json"].sub
    msg := "Error Userinfo sub not matching id_token sub"
}
