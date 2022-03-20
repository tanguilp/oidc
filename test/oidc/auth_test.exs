defmodule OIDC.AuthTest do
  use ExUnit.Case

  alias OIDC.Auth

  import OIDCTest.Support.Helpers

  @nonce "a nonce"

  setup_all do
    client = client_conf()
    op = op_metadata()

    Tesla.Mock.mock_global(fn
      %{method: :get, url: "https://example.com/.well-known/openid-configuration"} ->
        %Tesla.Env{status: 404}

      %{method: :post, url: "https://example.com/token"} ->
        resp = %{
          "access_token" => "an_access_token",
          "token_type" => "Bearer",
          "expires_in" => 600,
          "refresh_token" => "a_refresh_token",
          "id_token" => signed_id_token(op, client, nonce: @nonce)
        }

        resp_headers = [
          {"Cache-Control", "no-cache, no-store, max-age=0, stale-while-revalidate=300"},
          {"pragma", "no-cache"}
        ]

        %Tesla.Env{status: 200, body: resp, headers: resp_headers}
    end)

    [client: client, op: op]
  end

  describe "verify_challenge/2" do
    setup [:create_challenge]

    test "valid response with response type code", %{challenge: challenge} do
      challenge = Map.put(challenge, :response_type, "code") |> Auth.gen_challenge()

      op_response = %{
        "code" => "authz_code"
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type id_token", %{
      client: client,
      op: op,
      challenge: challenge
    } do
      challenge =
        Map.put(challenge, :response_type, "id_token")
        |> Auth.gen_challenge()
        |> Map.put(:nonce, @nonce)

      op_response = %{
        "id_token" => signed_id_token(op, client, nonce: @nonce)
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type id_token token", %{
      client: client,
      op: op,
      challenge: challenge
    } do
      challenge =
        Map.put(challenge, :response_type, "id_token token")
        |> Auth.gen_challenge()
        |> Map.put(:nonce, @nonce)

      op_response = %{
        "id_token" =>
          signed_id_token(
            op,
            client,
            nonce: @nonce,
            at_hash: token_hash("abcdef", List.first(op["jwks"]["keys"]))
          ),
        "access_token" => "abcdef",
        "token_type" => "bearer"
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type code id_token", %{
      client: client,
      op: op,
      challenge: challenge
    } do
      challenge =
        Map.put(challenge, :response_type, "code id_token")
        |> Auth.gen_challenge()
        |> Map.put(:nonce, @nonce)

      op_response = %{
        "code" => "authz_code",
        "id_token" =>
          signed_id_token(
            op,
            client,
            nonce: @nonce,
            c_hash: token_hash("authz_code", List.first(op["jwks"]["keys"]))
          )
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type code token", %{challenge: challenge} do
      challenge =
        Map.put(challenge, :response_type, "code token")
        |> Auth.gen_challenge()
        |> Map.put(:nonce, @nonce)

      op_response = %{
        "code" => "authz_code",
        "access_token" => "abcdef",
        "token_type" => "bearer"
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type code id_token token", %{
      client: client,
      op: op,
      challenge: challenge
    } do
      challenge =
        Map.put(challenge, :response_type, "code id_token token")
        |> Auth.gen_challenge()
        |> Map.put(:nonce, @nonce)

      op_response = %{
        "code" => "authz_code",
        "access_token" => "abcdef",
        "token_type" => "bearer",
        "id_token" =>
          signed_id_token(
            op,
            client,
            nonce: @nonce,
            at_hash: token_hash("abcdef", List.first(op["jwks"]["keys"])),
            c_hash: token_hash("authz_code", List.first(op["jwks"]["keys"]))
          )
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type code and valid iss resp parameter", %{
      challenge: challenge
    } do
      challenge =
        challenge
        |> Map.put(:response_type, "code")
        |> put_in([:server_metadata, "authorization_response_iss_parameter_supported"], true)
        |> Auth.gen_challenge()

      op_response = %{
        "code" => "authz_code",
        "iss" => challenge.issuer
      }

      assert {:ok, _} = Auth.verify_response(op_response, challenge)
    end

    test "valid response with response type code but invalid iss resp parameter", %{
      challenge: challenge
    } do
      challenge =
        challenge
        |> Map.put(:response_type, "code")
        |> put_in([:server_metadata, "authorization_response_iss_parameter_supported"], true)
        |> Auth.gen_challenge()

      op_response = %{
        "code" => "authz_code",
        "iss" => "not-the-original-issuer"
      }

      assert {:error, %OIDC.Auth.ProtocolError{}} = Auth.verify_response(op_response, challenge)
    end
  end

  describe "request_uri/2" do
    setup [:create_challenge]

    test "authorization endpoint retains its query parameters", %{challenge: challenge_opts} do
      challenge = Map.put(challenge_opts, :response_type, "code") |> Auth.gen_challenge()

      request_uri = Auth.request_uri(challenge, challenge_opts) |> URI.to_string()

      assert request_uri =~ "a=1"
    end
  end

  defp create_challenge(%{client: client, op: op} = context) do
    challenge = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      client_config: OIDCTest.Support.Helpers,
      redirect_uri: "https://rp.com/redirect_uri",
      server_metadata: op,
      id_token_iat_max_time_gap: 5
    }

    Map.put(context, :challenge, challenge)
  end

  defp token_hash(token, jwk) do
    hashed_token = :crypto.hash(JOSEUtils.JWK.sig_alg_digest(jwk), token)

    hashed_token
    |> binary_part(0, div(byte_size(hashed_token), 2))
    |> Base.url_encode64(padding: false)
  end
end
