defmodule OIDC.OP do
  alias OIDC.Auth.Challenge
  alias OIDC.IDToken

  defmodule JWKSRetrievalError do
    defexception [:reason]

    @impl true
    def message(%{reqason: reason}),
      do: "Could not retrieve the OP JWKS (reason: #{inspect(reason)})"
  end

  @doc """
  Returns the JWKs of an OpenID Provider (OP)

  The server metadata `"jwks"` field takes precedence over the server metadata `"jwks_uri"`
  field, which takes precedence over using the `"issuer"` field to retrieve the JWKs.
  """
  @spec jwks(Challenge.t() | IDToken.verification_data()) ::
  {:ok, [JOSEUtils.JWKS.t()]}
  | {:error, Exception.t()}
  def jwks(%{server_metadata: %{"jwks" => jwks}}) do
    {:ok, jwks["keys"]}
  end

  def jwks(%{server_metadata: %{"jwks_uri" => jwks_uri}}) do
    case JWKSURIUpdater.get_keys(jwks_uri) do
      {:ok, jwks} ->
        {:ok, jwks}

      {:error, reason} ->
        {:error, %JWKSRetrievalError{reason: reason}}
    end
  end

  def jwks(%{issuer: issuer} = validation_data) do
    oauth2_metadata_updater_opts = Map.get(validation_data, :oauth2_metadata_updater_opts) || []

    case Oauth2MetadataUpdater.get_metadata(issuer, oauth2_metadata_updater_opts) do
      {:ok, %{"jwks_uri" => jwks_uri}} ->
        case JWKSURIUpdater.get_keys(jwks_uri) do
          {:ok, jwks} ->
            {:ok, jwks}

          {:error, reason} ->
            {:error, %JWKSRetrievalError{reason: reason}}
        end

      {:ok, _} ->
        {:error, %JWKSRetrievalError{reason: "OP metadata has no `jwks_uri`"}}

      {:error, reason} ->
        {:error, %JWKSRetrievalError{reason: reason}}
    end
  end
end
