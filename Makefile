all:  token_resp_standard id_token_standard userinfo_standard  jwt_access_token_standard introspect_standard

token_resp_standard: 
	conftest test output/access_token_resp.json --policy standard-policies/access_token_resp_standard.rego --parser json || true


id_token_standard: 
	conftest test output/id_token.json --policy standard-policies/id_token_standard.rego --parser json  || true 


userinfo_standard: 
	conftest test output/userinfo.json --policy standard-policies/userinfo_standard.rego --parser json  || true 
	conftest parse --parser json output/id_token.json output/userinfo.json | conftest test --policy standard-policies/userinfo_sub_standard.rego --parser json -  || true 


jwt_access_token_standard: 
	[ -f output/access_token.json ] &&  conftest test output/access_token.json --policy standard-policies/jwt_access_token_standard.rego --parser json || true
	[ -f output/refresh_token.json ] && conftest test output/refresh_token.json --policy standard-policies/jwt_access_token_standard.rego --parser json || true 
	
introspect_standard: 
	[ -f output/introspect.json ] && conftest test output/introspect.json --policy standard-policies/introspect_standard.rego --parser json || true
	