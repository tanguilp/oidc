# OIDC

Convenience functions to work with OpenID Connect

It includes:
- functions to verify with ID tokens (`OIDC.IDToken.verify/3`, `OIDC.IDToken.verify_hash/4` and
`OIDC.IDToken.verify_hash_if_present/4`)
- functions to authenticate using OpenID Connect flows (`OIDC.Auth.gen_challenge/1`,
`OIDC.Auth.request_uri/2` and `OIDC.Auth.verify_response/2`)

## Installation

```elixir
def deps do
  [
    {:oidc, "~> 0.1.0"}
  ]
end
```
