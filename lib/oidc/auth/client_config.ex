defmodule OIDC.Auth.ClientConfig do
  @moduledoc """
  Behaviour to retrieve client configuration at runtime

  Client configuration is a map whose keys are those documented in
  [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)
  , those used being:
  - `"client_id"`
  - `"client_secret"`: the client secret to authenticate to OAuth2 / OpenID Connect
  API endpoints when the `"token_endpoint_auth_method"` is one of:
    - `"client_secret_post"`
    - `"client_secret_basic"`
    - `"client_secret_jwt"` (if a JWK is not used)
  - `"id_token_encrypted_response_alg"`
  - `"id_token_encrypted_response_enc"`
  - `"id_token_signed_response_alg"`
  - `"jwks"`: the client's JWKs (must be maps, will be used calling `JOSE.JWK.from_map/1`)
  - `"jwks_uri"`: the client's JWKs URI
  - `"token_endpoint_auth_method"`: the client's authentication method for the token endpoint
  """

  @type t :: %{optional(String.t()) => any()}

  defmodule MissingFieldError do
    defexception [:field]

    @impl true
    def message(%{field: field}), do: "Client `#{field}` field is not configured"
  end


  @doc """
  Returns the client configuration, or `nil` if not found
  """
  @callback get(client_id :: String.t()) :: t() | nil
end
