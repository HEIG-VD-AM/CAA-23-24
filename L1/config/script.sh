#!/bin/bash

RED='\033[0;31m'
RESET='\033[0m'

echo -e "${RED}STARTING SERVER AND CREATING KEYS${RESET}" 

init_output=$(vault operator init -key-shares=6 -key-threshold=2)

declare -a unseal_keys

while read -r line; do
    if [[ $line =~ Unseal\ Key\ [0-9]+:\ (.+) ]]; then
        unseal_keys+=("${BASH_REMATCH[1]}")
    fi
done <<< "$init_output"

root_token=$(echo "$init_output" | awk '/Initial Root Token:/ { print $NF }')

for key in "${unseal_keys[@]}"; do
    echo "$key"
done

export VAULT_TOKEN=$root_token

echo -e "${RED}UNSEALING THE VAULT${RESET}"

premiere_cle=${unseal_keys[0]}
seconde_cle=${unseal_keys[1]}
vault operator unseal $premiere_cle
vault operator unseal $seconde_cle

echo -e "${RED}VAULT LOGIN${RESET}"

vault login $VAULT_TOKEN

echo -e "${RED}ADMIN POLICY AND TOKEN CREATION${RESET}"

vault policy write admin ./admin-policy.hcl

vault token create -policy=admin -period=1h -no-default-policy

echo -e "${RED}ROOT CA${RESET}"

vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

vault write -field=certificate pki/root/generate/internal \
     common_name="HEIG-VD Root" \
     issuer_name="HEIG-VD-Root" \
     ttl=87600h > heig_root_ca.crt

vault write pki/roles/heig-root allow_any_name=true

vault write pki/config/urls \
     issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
     crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

echo -e "${RED}INTERMEDIATE CA${RESET}"

vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

vault write -format=json pki_int/intermediate/generate/internal \
     common_name="HEIG-VD Intermediate" \
     issuer_name="HEIG-VD-Root" \
     | jq -r '.data.csr' > pki_intermediate.csr

vault write -format=json pki/root/sign-intermediate \
     issuer_ref="HEIG-VD-Root" \
     csr=@pki_intermediate.csr \
     format=pem_bundle ttl="43800h" \
     | jq -r '.data.certificate' > intermediate.cert.pem

vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem

echo -e "${RED}INTRA POLICY,ROLE AND CERTIFICATE CREATION${RESET}"

vault write pki_int/roles/intra-dot-heig-vd-dot-ch \
     issuer_ref="$(vault read -field=default pki_int/config/issuers)" \
     allowed_domains="intra.heig-vd.ch" \
     allow_bare_domains=true \
     allow_subdomains=false \
     max_ttl="720h"

vault policy write intra ./intra-policy.hcl

vault write -format=json pki_int/issue/intra-dot-heig-vd-dot-ch \
     common_name="intra.heig-vd.ch" \
     format=pem_bundle ttl="24h" \
     | jq -r '.data.certificate' > intra.heig-vd.ch.pem

echo -e "${RED}WILDCARD CERTIFICATE CREATION${RESET}"

vault write pki_int/roles/heig-vd-dot-ch \
     issuer_ref="$(vault read -field=default pki_int/config/issuers)" \
     allowed_domains="heig-vd.ch" \
     allow_bare_domains=true \
     allow_subdomains=true \
     max_ttl="720h"
     
vault write -format=json pki_int/issue/heig-vd-dot-ch \
common_name="heig-vd.ch" \
format=pem_bundle ttl="24h" \
| jq -r '.data.certificate' > heig-vd.ch.pem

echo -e "${RED}CREATING USERS${RESET}"

vault auth enable userpass

vault write auth/userpass/users/toto \
    password=titi \
    policies=intra

vault write auth/userpass/users/admin \
    password=admin \
    policies=admin
