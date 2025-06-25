POLICY_ENTRY_POINTS := "-e identity/identity_provider_list"

[working-directory: 'policy']
@build-policy:
  echo "Building policy"
  @opa build -t wasm {{POLICY_ENTRY_POINTS}} .
  @tar xvf bundle.tar.gz -C ../ /policy.wasm
