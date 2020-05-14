defmodule OIDC.Auth.OPResponseError do
  @enforce_keys [:error]

  defexception [
    :error,
    :error_description,
    :error_uri
  ]

  @type t :: %__MODULE__{
    error: String.t(),
    error_description: String.t() | nil,
    error_uri: String.t() | nil
  }

  @impl true
  def message(%{error_description: error_description}), do: error_description
  def message(%{error: error}), do: error
end
