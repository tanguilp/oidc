defmodule OIDC.Client do
  alias OIDC.Auth.ClientConfig

  defmodule JWKSRetrievalError do
    defexception [:reason]

    @impl true
    def message(%{reqason: reason}),
      do: "Could not retrieve the client JWKS (reason: #{inspect(reason)})"
  end

  @doc """
  Returns the JWKs of a client

  The `"jwks"` field of the client confgiuration takes precedence over the `"jwks_uri"` field.
  """
  @spec jwks(ClientConfig.t()) :: {:ok, [JOSEUtils.JWKS.t()]} | {:error, Exception.t()}
  def jwks(%{"jwks" => jwks}) do
    {:ok, jwks["keys"]}
  end

  def jwks(%{"jwks_uri" => jwks_uri}) do
    case JWKSURIUpdater.get_keys(jwks_uri) do
      {:ok, jwks} ->
        {:ok, jwks}

      {:error, reason} ->
        {:error, %JWKSRetrievalError{reason: reason}}
    end
  end

  def jwks(_) do
    {:error, %ClientConfig.MissingFieldError{field: "jwks"}}
  end
end
