defmodule OIDC.Auth.OPResponseError do
  @enforce_keys [:error]

  defstruct [
    :error,
    :error_description,
    :error_uri
  ]

  @type t :: %__MODULE__{
    error: String.t(),
    error_description: String.t() | nil,
    error_uri: String.t() | nil
  }
end
