defmodule OIDC do
  @type access_token :: String.t()
  @type access_token_type :: String.t()
  @type acr :: String.t()
  @type amr :: String.t()
  @type auth_time :: non_neg_integer()
  @type claims :: %{optional(String.t()) => map()}
  @type client_id :: String.t()
  @type refresh_token :: String.t()
  @type id_token :: String.t()
  @type id_token_claims :: %{optional(String.t()) => any()}
  @type issuer :: String.t()
  @type nonce :: String.t()
  @type redirect_uri :: String.t()
  @type response_mode :: String.t()
  @type response_type :: String.t()
  @type scope :: String.t()
  @type server_metadata :: %{optional(String.t()) => any()}
  @type session_id :: String.t()
  @type subject :: String.t()
  @type ui_locale :: String.t()
end
