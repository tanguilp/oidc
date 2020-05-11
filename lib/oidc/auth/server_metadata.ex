defmodule OIDC.Auth.ServerMetadata do
  @moduledoc false

  #FIXME: move somewhere else

  alias OIDC.Auth.Challenge

  @spec get(OIDC.Auth.challenge_opts() | Challenge.t()) :: OIDC.server_metadata()
  def get(%Challenge{} = challenge) do
    get([
      server_metadata: challenge.server_metadata,
      issuer: challenge.issuer,
      oauth2_metadata_updater_opts: challenge.oauth2_metadata_updater_opts
    ])
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
end
