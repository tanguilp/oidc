defmodule OIDC.IDToken do
  @moduledoc """
  ID Token validation
  """

  alias OIDC.{
    Auth.ClientConfig,
    Client,
    OP
  }

  @typedoc """
  The serialized ID Token, for instance:

      eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  """
  @type serialized :: String.t()

  @typedoc """
  The ID token claims, for instance:

      %{
         "aud" => "client_1",
         "exp" => 1588689766,
         "iat" => 1588689736,
         "iss" => "https://example.com",
         "sub" => "user_1"
       }
  """
  @type claims :: %{optional(String.t()) => any()}

  @typedoc """
  Data needed to verify an ID Token
  """
  @type verification_data :: %{
    required(:client_id) => OIDC.client_id(),
    required(:issuer) => OIDC.issuer(),
    optional(:auth_time_required) => boolean(),
    optional(:id_token_iat_max_time_gap) => non_neg_integer(),
    optional(:jti_register) => module(),
    optional(:mandatory_acrs) => [OIDC.acr()],
    optional(:nonce) => OIDC.nonce(),
    optional(:oauth2_metadata_updater_opts) => Keyword.t(),
    optional(:server_metadata) => OIDC.server_metadata(),
    optional(atom()) => any()
  }

  defmodule DecryptionError do
    defexception message: "ID token could not be decrypted"
  end

  defmodule InvalidSignatureError do
    defexception message: "ID token signature verification failed"
  end

  defmodule MissingRequiredClaimError do
    @enforce_keys [:claim]

    defexception [:claim]

    @impl true
    def message(%{claim: claim}), do: "Missing mandatory claim `#{claim}` in returned ID token"
  end

  defmodule InvalidIssuerError do
    defexception message: "ID token issuer does not match the expected one"
  end

  defmodule InvalidAudienceError do
    defexception message: "ID token audience does not not match the client id"
  end

  defmodule InvalidAuthorizedPartyError do
    defexception message: "ID token azp does not not match the client id"
  end

  defmodule ExpiredError do
    defexception message: "The ID token has expired"
  end

  defmodule IssuedToFarFromNowError do
    defexception message: "The ID token has been issued to far in the past to be accepted (iat)"
  end

  defmodule InvalidNonceError do
    defexception message: "A nonce is expected in the ID token, or it does not match the expected one"
  end

  defmodule InvalidACRError do
    defexception message: "The returned ACR does not satisfy the expected conditions"
  end

  defmodule InvalidTokenHashError do
    @enforce_keys [:token_hash]

    defexception [:token_hash]

    @impl true
    def message(%{token_hash: token_hash}) do
      "Invalid token hash in ID token for `#{token_hash}`"
    end
  end

  defmodule ReplayedError do
    defexception message: "The ID token was reused"
  end

  @doc """
  Verifies an ID Token

  This function verifies:
  - the signature of the ID Token
  - the standard claims against their validation rules and validation data:
    - `"iss"`
    - `"aud"`
    - `"azp"`
    - `"exp"`
    - `"iat"`
    - `"nonce"`
    - `"acr"`
    - `"auth_time"`

  It does **not** verifies the `"c_hash"` and `"at_hash"` claims. See `verify_hash/4` and
  `verify_hash_if_present/4` for this.
  """
  @spec verify(
    serialized(),
    ClientConfig.t(),
    verification_data()
  ) :: {:ok, {claims(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def verify(serialized_id_token, client_conf, %_{} = verification_data) do
    # converts a %OIDC.Auth.Challenge{} to a map that supports the access protocol (contrary
    # to structs)
    verification_data =
      verification_data
      |> Map.from_struct()
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.into(%{})

    verify(serialized_id_token, client_conf, verification_data)
  end

  def verify(serialized_id_token, client_conf, verification_data) do
    with {:ok, serialized_id_token} <- maybe_decrypt_id_token(serialized_id_token, client_conf),
         {:ok, {jws_payload, jwk}} <-
           verify_signature(serialized_id_token, client_conf, verification_data),
         {:ok, id_token_claims} = Jason.decode(jws_payload),
         :ok <- verify_issuer(id_token_claims, verification_data),
         :ok <- verify_sub(id_token_claims),
         :ok <- verify_audience(id_token_claims, verification_data),
         :ok <- verify_azp(id_token_claims, verification_data),
         :ok <- verify_exp(id_token_claims),
         :ok <- verify_iat(id_token_claims, verification_data),
         :ok <- verify_nonce(id_token_claims, verification_data),
         :ok <- verify_acr(id_token_claims, verification_data),
         :ok <- verify_auth_time(id_token_claims, verification_data),
         :ok <- verify_not_replayed(id_token_claims, verification_data) do
      {:ok, {id_token_claims, jwk}}
    end
  end

  @spec maybe_decrypt_id_token(
    serialized(),
    ClientConfig.t()
  ) :: {:ok, String.t()} | {:error, Exception.t()}
  defp maybe_decrypt_id_token(id_token, client_config) do
    if JOSEUtils.is_jwe?(id_token) do
      case client_config do
        %{"id_token_encrypted_response_alg" => alg} ->
          enc = client_config["id_token_encrypted_response_enc"] || "A128CBC-HS256"

          with {:ok, jwks} <- Client.jwks(client_config),
               {:ok, {content, _jwk}} <- JOSEUtils.JWE.decrypt(id_token, jwks, [alg], [enc]) do
            {:ok, content}
          else
            :error ->
              {:error, %DecryptionError{}}

            {:error, _} = error ->
              error
          end

        _ ->
          {:error, %ClientConfig.MissingFieldError{field: "id_token_encrypted_response_alg"}}
      end
    else
      {:ok, id_token}
    end
  end

  @spec verify_signature(
    serialized(),
    ClientConfig.t(),
    verification_data()
  ) :: {:ok, {binary(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  defp verify_signature(serialized_id_token, client_config, verification_data) do
    alg = client_config["id_token_signed_response_alg"] || "RS256"

    with {:ok, jwks} <- OP.jwks(verification_data),
         {:ok, result} <- JOSEUtils.JWS.verify(serialized_id_token, jwks, [alg]) do
      {:ok, result}
    else
      :error ->
        {:error, %InvalidSignatureError{}}

      {:error, _} = error ->
        error
    end
  end

  @spec verify_issuer(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_issuer(%{"iss" => iss}, verification_data) do
    if iss == verification_data[:issuer] do
      :ok
    else
      {:error, %InvalidIssuerError{}}
    end
  end

  defp verify_issuer(_, _) do
    {:error, %MissingRequiredClaimError{claim: "iss"}}
  end

  @spec verify_sub(claims()) :: :ok | {:error, Exception.t()}
  defp verify_sub(%{"sub" => _}), do: :ok
  defp verify_sub(_), do: {:error, %MissingRequiredClaimError{claim: "sub"}}

  @spec verify_audience(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_audience(%{"aud" => aud}, verification_data) do
    case aud do
      audiences when is_list(audiences) ->
        verification_data[:client_id] in audiences

      audience when is_binary(audience) ->
        verification_data[:client_id] == audience
    end
    |> if do
      :ok
    else
      {:error, %InvalidAudienceError{}}
    end
  end

  defp verify_audience(_, _) do
    {:error, %MissingRequiredClaimError{claim: "aud"}}
  end

  @spec verify_azp(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_azp(claims, verification_data) do
    aud = claims["aud"]

    if is_list(aud) do
      if claims["azp"] == verification_data[:client_id] do
        :ok
      else
        {:error, %InvalidAuthorizedPartyError{}}
      end
    else
      :ok
    end
  end

  @spec verify_exp(claims()) :: :ok | {:error, Exception.t()}
  defp verify_exp(%{"exp" => exp}) when is_integer(exp) do
    if :os.system_time(:seconds) < exp do
      :ok
    else
      {:error, %ExpiredError{}}
    end
  end

  defp verify_exp(_) do
    {:error, %MissingRequiredClaimError{claim: "exp"}}
  end

  @spec verify_iat(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_iat(%{"iat" => iat}, verification_data) when is_integer(iat) do
    id_token_iat_max_time_gap = verification_data[:id_token_iat_max_time_gap] || 0

    if System.system_time(:second) - iat <= id_token_iat_max_time_gap do
      :ok
    else
      {:error, %IssuedToFarFromNowError{}}
    end
  end

  defp verify_iat(_, _) do
    {:error, %MissingRequiredClaimError{claim: "iat"}}
  end

  @spec verify_nonce(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_nonce(claims, verification_data) do
    case verification_data[:nonce] do
      nonce when is_binary(nonce) ->
        if nonce == claims["nonce"] do
          :ok
        else
          {:error, %InvalidNonceError{}}
        end

      nil ->
        :ok
    end
  end

  @spec verify_acr(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_acr(claims, %{mandatory_acrs: mandatory_acrs}) do
    if claims["acr"] in mandatory_acrs do
      :ok
    else
      {:error, %InvalidACRError{}}
    end
  end

  defp verify_acr(_, _) do
    :ok
  end

  @spec verify_auth_time(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_auth_time(deserialized_id_token, verification_data) do
    if verification_data[:auth_time_required] do
      if is_integer(deserialized_id_token["auth_time"]) do
        :ok
      else
        {:error, %MissingRequiredClaimError{claim: "auth_time"}}
      end
    else
      :ok
    end
  end

  @spec verify_not_replayed(claims(), verification_data()) :: :ok | {:error, Exception.t()}
  defp verify_not_replayed(%{"nonce" => nonce}, verification_data) do
    case verification_data[:jti_register] do
      impl when is_atom(impl) ->
        if impl.registered?(nonce) do
          {:error, %ReplayedError{}}
        else
          :ok
        end

      _ ->
        :ok
    end
  end

  defp verify_not_replayed(_, _) do
    :ok
  end

  @doc """
  Verifies an hash-claim of an ID token, if present in the ID token
  
  The token hash name is one of:
  - `"c_hash"`
  - `"at_hash"`

  The JWK to be passed as a parameter is the JWK that has been used to validate the ID token
  signature.
  """
  @spec verify_hash_if_present(
    String.t(),
    String.t(),
    claims(),
    JOSEUtils.JWK.t()
  ) :: :ok | {:error, Exception.t()}
  def verify_hash_if_present(token_hash_name, token, claims, jwk) do
    if claims[token_hash_name] do
      verify_hash(token_hash_name, token, claims, jwk)
    else
      :ok
    end
  end

  @doc """
  Verifies an hash-claim of an ID token
  
  The token hash name is one of:
  - `"c_hash"`
  - `"at_hash"`

  The JWK to be passed as a parameter is the JWK that has been used to validate the ID token
  signature.
  """
  @spec verify_hash(
    String.t(),
    String.t(),
    claims(),
    JOSEUtils.JWK.t()
  ) :: :ok | {:error, Exception.t()}
  def verify_hash(token_hash_name, token, claims, jwk) do
    hashed_token = :crypto.hash(JOSEUtils.JWK.sig_alg_digest(jwk), token)

    computed_token_hash =
      hashed_token
      |> String.slice(0, div(byte_size(hashed_token), 2) - 1)
      |> Base.url_encode64(padding: false)

    if computed_token_hash == claims[token_hash_name] do
      :ok
    else
      {:error, %InvalidTokenHashError{token_hash: token_hash_name}}
    end
  end
end
