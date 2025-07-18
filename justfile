POLICY_ENTRY_POINTS := \
" -e identity/check_token" +\
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
" -e identity/mapping_delete" +\
" -e identity/role_list" +\
" -e identity/role_show" +\
" -e identity/role_create" +\
" -e identity/role_update" +\
" -e identity/role_delete" +\
" -e identity/role_assignment_list" +\
" -e identity/group_list" +\
" -e identity/group_show" +\
" -e identity/group_create" +\
" -e identity/group_update" +\
" -e identity/group_delete" +\
" -e identity/user_list" +\
" -e identity/user_show" +\
" -e identity/user_create" +\
" -e identity/user_update" +\
" -e identity/user_delete" +\
" -e identity/user_group_list"

[working-directory: 'policy']
@build-policy:
  echo "Building policy"
  @opa build -t wasm {{POLICY_ENTRY_POINTS}} .
  @tar xvf bundle.tar.gz -C ../ /policy.wasm
