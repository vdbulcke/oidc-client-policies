# Rego Policies For OIDC Client Output Validation

[conftest](https://www.conftest.dev/) Rego policies for validating OIDC responses.

## Pre-requisites

* [Install conftest](https://www.conftest.dev/install/)
* (optional) [Install oidc-client](https://vdbulcke.github.io/oidc-client-demo/install/)

## tl:dr

* Generate json output files with [oidc-client](https://github.com/vdbulcke/oidc-client-demo)

```bash
## create output dir
mkdir -p output/
## generate  json output files
oidc-client client --config my-config.yaml  --output --output-dir output/
```

* validate outputs against standard policies

```bash
make all
```

## Standard Policies

Standard policies, based on various OAuth2 or OIDC RFC, are defined in `standard-policies/`. 
