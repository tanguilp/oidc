defmodule OIDC.Auth.Challenge do
  @moduledoc """
  OpenID Connect challenge
  """

  @enforce_keys [:client_id, :client_config, :issuer, :redirect_uri, :scope]

  defstruct [
    :auth_time_required,
    :client_id,
    :client_config,
    :id_token_iat_max_time_gap,
    :issuer,
    :mandatory_acrs,
    :nonce,
    :oauth2_metadata_updater_opts,
    :redirect_uri,
    :response_type,
    :scope,
    :server_metadata,
    :state_param,
    :token_endpoint_tesla_auth_middleware_opts
  ]

  @type t :: %__MODULE__{
    auth_time_required: boolean(),
    client_id: OIDC.client_id(),
    client_config: module(),
    id_token_iat_max_time_gap: non_neg_integer() | nil,
    issuer: OIDC.issuer(),
    mandatory_acrs: [OIDC.acr()] | nil,
    nonce: OIDC.nonce() | nil,
    oauth2_metadata_updater_opts: Keyword.t() | nil,
    redirect_uri: OIDC.redirect_uri(),
    response_type: OIDC.response_type(),
    scope: [OIDC.scope()],
    server_metadata: OIDC.server_metadata() | nil, #TODO: rename op_metadata
    state_param: String.t(),
    token_endpoint_tesla_auth_middleware_opts: Keyword.t() | nil
  }
end
