defmodule OIDC.Auth do
  @moduledoc """
  Create and verify OpenID Connect challenges for a specific OP
  """

  alias OIDC.Auth.{
    Challenge,
    ClientConfig,
    OPResponseError,
    OPResponseSuccess,
    ProtocolError,
    ServerMetadata
  }
  alias OIDC.IDToken

  @type challenge_opts :: [challenge_opt()]

  @type challenge_opt ::
  {:acr_values, [OIDC.acr()]}
  | {:claims, OIDC.claims()}
  | {:client_config, module()}
  | {:client_id, OIDC.client_id()}
  | {:display, String.t()}
  | {:id_token_iat_max_time_gap, non_neg_integer()}
  | {:issuer, OIDC.issuer()}
  | {:login_hint, String.t()}
  | {:max_age, non_neg_integer()}
  | {:oauth2_metadata_updater_opts, Keyword.t()}
  | {:prompt, String.t()}
  | {:redirect_uri, String.t()}
  | {:response_mode, OIDC.response_mode()}
  | {:response_type, OIDC.response_type()}
  | {:scope, [OIDC.scope()]}
  | {:server_metadata, OIDC.server_metadata()}
  | {:ui_locales, [OIDC.ui_locale()]}
  | {:use_nonce, :when_mandatory | :always}

  @type verify_opts() :: [verify_opt()]
  @type verify_opt() ::
  {:jti_register, module()}
  | {:tesla_auth_middleware_opts, Keyword.t()}
  | {:tesla_middlewares, [Tesla.Client.middleware()]}

  @type op_response :: %{optional(String.t()) => any()}

  @allowed_response_modes [
    "query",
    "fragment",
    "form_post"
  ]

  @allowed_response_types [
    "code",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
  "code id_token token"
]

  @doc """
  Generates an OpenID Connect challenge or raise an exception if a parameter is missing

  This challenge is to be passed back to `verify_challenge/2` when redirected back from the
  OpenID Provider

  Note that a code verifier is automatically generated when supported by the OP and a code
  is requested by the response type.

  ## Options
  - `:acr_values`: voluntary set of ACRs to be requested via the `"acr_values"` parameter
  - `:claims`: claims requested in the `"claims"` parameter
  - `:client_config` **[Mandatory]**: a module that implements the `OIDC.Auth.ClientConfig`
  behaviour
  - `:client_id` **[Mandatory]**: the client id of the application using this library and
  initiating the request
  - `:dispay`: the display OpenID Connect parameter (mostly unused)
  - `:id_token_iat_max_time_gap`: max time gap to accept an ID token, in seconds. Defaults to 0
  - `:issuer` **[Mandatory]**: the OpenID Provider (OP) issuer. Metadata and JWKs are
  automatically retrieved from it
  - `:login_hint`: the login hint OpenID Connect parameter
  - `:max_age`: the max age OpenID Connect parameter
  - `:oauth2_metadata_updater_opts`: options that will be passed to `Oauth2MetadataUpdater`
  - `:prompt`: the prompt OpenID Connect parameter
  - `:redirect_uri` **[Mandatory]**: the redirect URI the OP has to use for redirect
  - `:response_mode`: one of:
    - `"query"`
    - `"fragment"`
    - `"form_post"`
    - `nil` which means that the OP decides for the response mode
  - `:response_type` **[Mandatory]**: one of:
    - `"code"`
    - `"id_token"`
    - `"id_token token"`
    - `"code token"`
    - `"code id_token"`
    - `"code id_token token"`
  - `:scope`: a list of scopes (`[String.t()]`) to be requested. The `"openid"` scope
  is automatically requested
  - `:server_metadata`: server metadata that takes precedence over those automatically retrieve
  on the OP configuration (requested from the issuer). Usefull when the OP does not support
  OpenID Connect discovery, or the override one or more parameters
  - `ui_locales`: the ui locales OpenID Connect parameter
  - `:use_nonce`: one of:
    - `:when_mandatory` [*Default*]: a nonce is included when using the implicit and
    hybrid flows
    - `:always`: always include a nonce (i.e. also in the code flow in which it is
    optional)
  """
  @spec gen_challenge(challenge_opts()) :: Challenge.t() | no_return()
  def gen_challenge(opts) do
    unless opts[:issuer], do: raise "missing issuer"
    unless opts[:client_id], do: raise "missing client_id"
    unless opts[:client_config], do: raise "missing client configuration callback module"
    unless opts[:redirect_uri], do: raise "missing redirect URI"
    unless opts[:response_type] in @allowed_response_types do
      raise "Invalid response mode, must be one of: #{inspect(@allowed_response_types)}"
    end

    scope =
      MapSet.new(opts[:scope] || [])
      |> MapSet.put("openid")
      |> MapSet.to_list()

    %Challenge{
      auth_time_required: auth_time_required?(opts),
      client_id: opts[:client_id],
      client_config: opts[:client_config],
      id_token_iat_max_time_gap: opts[:id_token_iat_max_time_gap],
      issuer: opts[:issuer],
      mandatory_acrs: mandatory_acrs(opts[:claims]),
      nonce: maybe_gen_nonce(opts),
      oauth2_metadata_updater_opts: opts[:oauth2_metadata_updater_opts],
      pkce_code_verifier: maybe_gen_pkce_code_verifier(opts),
      redirect_uri: opts[:redirect_uri],
      response_type: opts[:response_type],
      scope: scope,
      server_metadata: opts[:server_metadata],
      state_param: gen_secure_random_string()
    }
  end

  @doc """
  Verifies an OpenID Connect challenge against the OP's response

  ## Options

  - `:jti_register`: a module implementing the `JTIRegister` behaviour, used to check against
  ID token replay
  - `:tesla_middlewares`: `Tesla` middlewares added to outbound request (for exemple requests
  to the token endpoint)
  - `:tesla_auth_middleware_opts`: additional `Keyword.t()` options to be passed as options to
  the `TeslaOAuth2ClientAuth` authentication middleware
  """
  @spec verify_response(
    op_response(),
    Challenge.t(),
    verify_opts()
  ) :: {:ok, OPResponseSuccess.t()} | {:error, OPResponseError.t()} | {:error, Exception.t()}
  def verify_response(op_response, challenge, verify_opts \\ [])

  def verify_response(%{"error" => _} = op_response, _challenge, _opts) do
    {
      :error,
      %OPResponseError{
        error: op_response["error"],
        error_description: op_response["error_description"],
        error_uri: op_response["error_uri"]
      }
    }
  end

  def verify_response(op_response, challenge, opts) do
    with :ok <- verify_response_params(op_response, challenge),
         {:ok, client_config} <- client_config(challenge),
         {:ok, response} <- validate_op_response(op_response, challenge, client_config, opts) do
      {:ok, response}
    end
  end

  @doc """
  Generates an OpenID Connect request URI from a challenge and associated options
  """
  @spec request_uri(Challenge.t(), challenge_opts()) :: URI.t()
  def request_uri(challenge, opts) do
    authorization_endpoint =
      ServerMetadata.get(opts)["authorization_endpoint"] ||
      raise "Unable to retrieve `authorization_endpoint` from server metadata or configuration"

    if opts[:response_mode] && opts[:response_mode] not in @allowed_response_modes do
      raise "Invalid response mode, must be one of: #{inspect(@allowed_response_modes)}"
    end

    {code_challenge, code_challenge_method} = maybe_hash_code_verifier_and_method(challenge, opts)

    params =
      Map.new()
      |> Map.put(:acr_values, opts[:acr_values])
      |> Map.put(:claims, opts[:claims])
      |> Map.put(:client_id, challenge.client_id)
      |> Map.put(:code_challenge, code_challenge)
      |> Map.put(:code_challenge_method, code_challenge_method)
      |> Map.put(:display, opts[:display])
      |> Map.put(:id_token_hint, opts[:id_token_hint])
      |> Map.put(:login_hint, opts[:login_hint])
      |> Map.put(:max_age, opts[:max_age])
      |> Map.put(:nonce, challenge.nonce)
      |> Map.put(:prompt, opts[:prompt])
      |> Map.put(:redirect_uri, challenge.redirect_uri)
      |> Map.put(:response_mode, opts[:response_mode])
      |> Map.put(:response_type, challenge.response_type)
      |> Map.put(:scope, challenge.scope)
      |> Map.put(:state, challenge.state_param)
      |> Map.put(:ui_locales, opts[:ui_locales])
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.filter(fn {_k, v} -> v != [] end)
      |> Enum.map(fn
          {k, [_ | _] = v} -> {k, Enum.join(v, " ")}

          {k, %{} = v} -> {k, Jason.encode!(v)}

          {k, v} -> {k, to_string(v)}
        end
      )
      |> Enum.into(%{})

    authorization_endpoint_uri = URI.parse(authorization_endpoint)

    query =
      URI.decode_query(authorization_endpoint_uri.query || "")
      |> Map.merge(params)
      |> URI.encode_query()

    authorization_endpoint_uri
    |> Map.put(:query, query)
    |> Map.put(:fragment, nil)
  end

  @spec maybe_hash_code_verifier_and_method(Challenge.t(), challenge_opts()) ::
  {String.t() | nil, String.t() | nil}
  defp maybe_hash_code_verifier_and_method(%Challenge{pkce_code_verifier: nil}, _opts) do
    {nil, nil}
  end

  defp maybe_hash_code_verifier_and_method(challenge, opts) do
    methods = ServerMetadata.get(opts)["code_challenge_methods_supported"] || []

    if "S256" in methods do
      {
        :crypto.hash(:sha256, challenge.pkce_code_verifier) |> Base.url_encode64(padding: false),
        "S256"
      }
    else
      if "plain" in methods do
        {challenge.pkce_code_verifier, "plain"}
      else
        {nil, nil}
      end
    end
  end

  @spec auth_time_required?(challenge_opts()) :: boolean()
  defp auth_time_required?(opts) do
    cond do
      is_integer(opts[:max_age]) ->
        true

      opts[:claims]["id_token"]["auth_time"]["essential"] == true ->
        true

      true ->
        false
    end
  end

  @spec mandatory_acrs(String.t() | nil) :: [OIDC.acr()] | nil
  defp mandatory_acrs(%{"id_token" =>
    %{"acr" =>
      %{"essential" => true, "value" => acr}
    }
  }) do
    [acr]
  end

  defp mandatory_acrs(%{"id_token" =>
    %{"acr" =>
      %{"essential" => true, "values" => acrs}
    }
  }) do
    acrs
  end

  defp mandatory_acrs(_) do
    nil
  end

  @spec maybe_gen_nonce(challenge_opts()) :: String.t() | nil
  defp maybe_gen_nonce(opts) do
    case opts[:use_nonce] do
      :always ->
        gen_secure_random_string()

      _ ->
        # implicit & hybrid flows
        if opts[:response_type] in [
            "id_token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token"
          ]
        do
          gen_secure_random_string()
        end
    end
  end

  @spec maybe_gen_pkce_code_verifier(challenge_opts()) :: String.t() | nil
  defp maybe_gen_pkce_code_verifier(opts) do
    if opts[:response_type] in ["code", "code id_token", "code token", "code id_token token"] do
      case ServerMetadata.get(opts) do
        %{"code_challenge_methods_supported" => [_ | _]} ->
          gen_secure_random_string()

        _ ->
          nil
      end
    end
  end

  @spec verify_response_params(op_response(), Challenge.t()) :: :ok | {:error, Exception.t()}
  defp verify_response_params(op_response, challenge) do
    case challenge.response_type do
      "code" ->
        match?(%{"code" => _}, op_response)

      "id_token" ->
        match?(%{"id_token" => _}, op_response)

      "id_token token" ->
        match?(%{"id_token" =>_, "access_token" => _, "token_type" => _}, op_response)

      "code id_token" ->
        match?(%{"code" => _, "id_token" =>_}, op_response)

      "code token" ->
        match?(%{"code" => _, "access_token" =>_, "token_type" => _}, op_response)

      "code id_token token" ->
        match?(%{"code" => _, "id_token" => _, "access_token" =>_, "token_type" => _}, op_response)

    end
    |> if do
      :ok
    else
      {:error, %ProtocolError{error: :missing_response_params}}
    end
  end

  @spec client_config(Challenge.t()) :: {:ok, ClientConfig.t()} | {:error, Exception.t()}
  defp client_config(challenge) do
    case challenge.client_config.get(challenge.client_id) do
      %{} = client_config ->
        {:ok, client_config}

      _ ->
        {:error, %ProtocolError{error: :missing_client_config}}
    end
  end

  @spec validate_op_response(
    op_response(),
    Challenge.t(),
    ClientConfig.t(),
    verify_opts()
  ) :: {:ok, OPResponseSuccess.t()} | {:error, Exception.t()}
  defp validate_op_response(
    %{"code" => code},
    %Challenge{response_type: "code"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, token_endpoint_response} <- exchange_code(code, challenge, client_config, opts),
         :ok <- validate_token_endpoint_response(token_endpoint_response),
         id_token = token_endpoint_response["id_token"],
         {:ok, {claims, _jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(token_endpoint_response, challenge)
    do
      {
        :ok,
        %OPResponseSuccess{
          access_token: token_endpoint_response["access_token"],
          access_token_expires_in: token_endpoint_response["expires_in"],
          access_token_type: token_endpoint_response["token_type"],
          refresh_token: token_endpoint_response["refresh_token"],
          id_token: id_token,
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  defp validate_op_response(
    %{"id_token" => id_token} = params,
    %Challenge{response_type: "id_token"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, {claims, _jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(params, challenge)
    do
      {
        :ok,
        %OPResponseSuccess{
          id_token: id_token,
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  defp validate_op_response(
    %{"id_token" => id_token, "access_token" => access_token} = params,
    %Challenge{response_type: "id_token token"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(params, challenge),
         :ok <- IDToken.verify_hash("at_hash", access_token, claims, jwk)
    do
      {
        :ok,
        %OPResponseSuccess{
          access_token: access_token,
          access_token_expires_in: params["expires_in"],
          access_token_type: params["token_type"],
          id_token: params["id_token"],
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  defp validate_op_response(
    %{"code" => code, "id_token" => id_token},
    %Challenge{response_type: "code id_token"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         :ok <- IDToken.verify_hash("c_hash", code, claims, jwk),
         {:ok, token_endpoint_response} <- exchange_code(code, challenge, client_config, opts),
         :ok <- validate_token_endpoint_response(token_endpoint_response),
         id_token = token_endpoint_response["id_token"],
         access_token = token_endpoint_response["access_token"],
         # we through away the first ID token, because the new one must be the same except
         # it can contains more claims
         {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(token_endpoint_response, challenge),
         :ok <- IDToken.verify_hash_if_present("at_hash", access_token, claims, jwk),
         :ok <- IDToken.verify_hash_if_present("c_hash", code, claims, jwk)
    do
      {
        :ok,
        %OPResponseSuccess{
          access_token: access_token,
          access_token_expires_in: token_endpoint_response["expires_in"],
          access_token_type: token_endpoint_response["token_type"],
          refresh_token: token_endpoint_response["refresh_token"],
          id_token: id_token,
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  defp validate_op_response(
    %{"code" => code, "access_token" => _access_token},
    %Challenge{response_type: "code token"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, token_endpoint_response} <- exchange_code(code, challenge, client_config, opts),
         :ok <- validate_token_endpoint_response(token_endpoint_response),
         id_token = token_endpoint_response["id_token"],
         access_token = token_endpoint_response["access_token"],
         {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(token_endpoint_response, challenge),
         :ok <- IDToken.verify_hash_if_present("at_hash", access_token, claims, jwk),
         :ok <- IDToken.verify_hash_if_present("c_hash", code, claims, jwk)
    do
      {
        :ok,
        %OPResponseSuccess{
          access_token: access_token,
          access_token_expires_in: token_endpoint_response["expires_in"],
          access_token_type: token_endpoint_response["token_type"],
          refresh_token: token_endpoint_response["refresh_token"],
          id_token: id_token,
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  defp validate_op_response(
    %{"code" => code, "id_token" => id_token, "access_token" => access_token},
    %Challenge{response_type: "code id_token token"} = challenge,
    client_config,
    opts
  ) do
    verification_data = verification_data(challenge, opts)

    with {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         :ok <- IDToken.verify_hash("at_hash", access_token, claims, jwk),
         :ok <- IDToken.verify_hash("c_hash", code, claims, jwk),
         {:ok, token_endpoint_response} <- exchange_code(code, challenge, client_config, opts),
         :ok <- validate_token_endpoint_response(token_endpoint_response),
         id_token = token_endpoint_response["id_token"],
         access_token = token_endpoint_response["access_token"],
         # we through away the first ID token, because the new one must be the same except
         # it can contains more claims
         {:ok, {claims, jwk}} <- IDToken.verify(id_token, client_config, verification_data),
         {:ok, granted_scopes} <- granted_scopes(token_endpoint_response, challenge),
         :ok <- IDToken.verify_hash_if_present("at_hash", access_token, claims, jwk),
         :ok <- IDToken.verify_hash_if_present("c_hash", code, claims, jwk)
    do
      {
        :ok,
        %OPResponseSuccess{
          access_token: access_token,
          access_token_expires_in: token_endpoint_response["expires_in"],
          access_token_type: token_endpoint_response["token_type"],
          refresh_token: token_endpoint_response["refresh_token"],
          id_token: id_token,
          id_token_claims: claims,
          granted_scopes: granted_scopes
        }
      }
    end
  end

  @spec validate_token_endpoint_response(map()) :: :ok | {:error, Exception.t()}
  defp validate_token_endpoint_response(%{
      "access_token" => _,
      "token_type" => _,
      "id_token" => _,
    }
  ) do
    :ok
  end

  defp validate_token_endpoint_response(_) do
    {:error, %ProtocolError{error: :token_endpoint_invalid_response}}
  end

  @spec exchange_code(
    String.t(),
    Challenge.t(),
    ClientConfig.t(),
    verify_opts()
  ) :: {:ok, map()} | {:error, Exception.t()}
  defp exchange_code(code, challenge, client_config, opts) do
    token_endpoint = ServerMetadata.get(challenge)["token_endpoint"] ||
      raise "Unable to retrieve `token_endpoint` from server metadata or configuration"

    body = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "redirect_uri" => challenge.redirect_uri
    }
    |> maybe_set_code_verifier(challenge)

    with {:ok, middlewares} <- tesla_middlewares(challenge, client_config, opts) do
      http_client = Tesla.client(middlewares)

      case Tesla.post(http_client, token_endpoint, body) do
        {:ok, %Tesla.Env{status: 200, body: body}} ->
          {:ok, body}

        {:ok, %Tesla.Env{status: status}} ->
          {:error, %ProtocolError{error: :token_endpoint_invalid_http_status, details: status}}

        {:error, _} ->
          {:error, %ProtocolError{error: :token_endpoint_http_error}}
      end
    end
  end

  @spec maybe_set_code_verifier(map(), Challenge.t()) :: map()
  defp maybe_set_code_verifier(body, %Challenge{pkce_code_verifier: nil}), do: body
  defp maybe_set_code_verifier(body, challenge),
    do: Map.put(body, "code_verifier", challenge.pkce_code_verifier)

  @spec tesla_middlewares(
    Challenge.t(),
    ClientConfig.t(),
    verify_opts()
  ) :: {:ok, [Tesla.Client.middleware()]} | {:error, Exception.t()}
  defp tesla_middlewares(challenge, client_config, opts) do
    auth_method = client_config["token_endpoint_auth_method"] || "client_secret_basic"

    case TeslaOAuth2ClientAuth.implementation(auth_method) do
      {:ok, authenticator} ->
        middleware_opts = Map.merge(
          opts[:tesla_auth_middleware_opts] || %{},
          %{
            client_id: challenge.client_id,
            client_config: client_config,
            server_metadata: ServerMetadata.get(challenge)
          }
        )

        {
          :ok,
          [{authenticator, middleware_opts}]
          ++ [Tesla.Middleware.FormUrlencoded]
          ++ [Tesla.Middleware.DecodeJson]
          ++ (opts[:tesla_middlewares] || [])
          ++ Application.get_env(:oidc, :tesla_middlewares, [])
        }

      {:error, _} ->
        {:error, %ProtocolError{error: :token_endpoint_authenticator_not_found}}
    end
  end

  @spec granted_scopes(
    op_response(),
    Challenge.t()
  ) :: {:ok, [OIDC.scope()]} | {:error, Exception.t()}
  defp granted_scopes(%{"scope" => scope_param}, _challenge) do
    case OAuth2Utils.Scope.Set.from_scope_param(scope_param) do
      {:ok, scope_set} ->
        {:ok, MapSet.to_list(scope_set)}

      {:error, _} ->
        {:error, %ProtocolError{error: :op_response_malformed_scope_param}}
    end
  end

  defp granted_scopes(_op_response, challenge) do
    {:ok, challenge.scope}
  end

  @spec gen_secure_random_string() :: String.t()
  defp gen_secure_random_string() do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  @spec verification_data(Challenge.t(), verify_opts()) :: OIDC.IDToken.verification_data()
  defp verification_data(challenge, opts) do
    challenge
    |> Map.from_struct()
    |> Map.put(:jti_register, opts[:jti_register])
    |> Enum.reject(fn {_k, v} -> v == nil end)
    |> Enum.into(%{})
  end
end
