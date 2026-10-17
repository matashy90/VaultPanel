# Least-privilege policy for the OnePane background monitor token.
# vault policy write onepane-monitor onepane-monitor.hcl
# vault token create -policy=onepane-monitor -period=768h -display-name=onepane-monitor
# Use a periodic token and renew it, or an AppRole/auth method of your own; the monitor does not renew tokens.

path "auth/token/lookup-self"                          { capabilities = ["read"] }
path "sys/internal/ui/mounts"                          { capabilities = ["read"] }
# Listing token accessors requires sudo in Vault; this is the only reason it is here.
path "auth/token/accessors"                            { capabilities = ["list", "sudo"] }
path "auth/token/lookup-accessor"                      { capabilities = ["update"] }
path "+/certs"                                         { capabilities = ["list"] }
path "+/cert/*"                                        { capabilities = ["read"] }
path "auth/+/role"                                     { capabilities = ["list"] }
path "auth/+/role/+/secret-id"                         { capabilities = ["list"] }
path "auth/+/role/+/secret-id-accessor/lookup"         { capabilities = ["update"] }
