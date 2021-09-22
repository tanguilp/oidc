defmodule OIDC.Utils.ServerMetadata do
  @moduledoc false

  alias OIDC.Auth.Challenge
  alias OIDC.IDToken

  @spec get(OIDC.Auth.challenge_opts() | Challenge.t()) :: OIDC.server_metadata()
  def get(%Challenge{} = challenge) do
    get(
      server_metadata: challenge.server_metadata,
      issuer: challenge.issuer,
      oauth2_metadata_updater_opts: challenge.oauth2_metadata_updater_opts
    )
  end

  def get(opts) do
    local_server_metadata = opts[:server_metadata] || %{}
    oauth2_metadata_updater_opts = opts[:oauth2_metadata_updater_opts] || []

    Oauth2MetadataUpdater.get_metadata(opts[:issuer], oauth2_metadata_updater_opts)
    |> case do
      {:ok, loaded_server_metadata} ->
        Map.merge(loaded_server_metadata, local_server_metadata)

      {:error, _} ->
        local_server_metadata
    end
  end

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
