defmodule OIDC.Auth.OPResponseSuccess do
  @moduledoc """
  Data returned by the OP in case of authentication and authorization success, and successful
  validation of this returned data
  """

  @enforce_keys [:id_token, :id_token_claims]

  defstruct [
    :access_token,
    :access_token_expires_in,
    :access_token_type,
    :refresh_token,
    :id_token,
    :id_token_claims,
    :granted_scopes
  ]

  @type t :: %__MODULE__{
          access_token: OIDC.access_token() | nil,
          access_token_expires_in: non_neg_integer() | nil,
          access_token_type: OIDC.access_token_type() | nil,
          refresh_token: OIDC.refresh_token() | nil,
          id_token: OIDC.id_token(),
          id_token_claims: OIDC.id_token_claims(),
          granted_scopes: [OIDC.scope()]
        }
end
