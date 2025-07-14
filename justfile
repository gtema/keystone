POLICY_ENTRY_POINTS := \
" -e identity/validate_token" +\
" -e identity/identity_provider_list" +\
" -e identity/identity_provider_show" +\
" -e identity/identity_provider_create" +\
" -e identity/identity_provider_update" +\
" -e identity/identity_provider_delete" +\
" -e identity/mapping_list" +\
" -e identity/mapping_show" +\
" -e identity/mapping_create" +\
" -e identity/mapping_update" +\
" -e identity/mapping_delete"

[working-directory: 'policy']
@build-policy:
  echo "Building policy"
  @opa build -t wasm {{POLICY_ENTRY_POINTS}} .
  @tar xvf bundle.tar.gz -C ../ /policy.wasm
