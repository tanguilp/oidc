defmodule OIDC.IDTokenTest do
  use ExUnit.Case

  alias OIDC.IDToken

  setup_all do
    [client: client_conf(), op: op_metadata()]
  end

  test "valid signed ID token is verified", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client)

    assert {:ok, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "valid encrypted ID token is verified", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client) |> encrypt(client)

    assert {:ok, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "valid signed ID token with mandatory acr and auth_time is verified", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      mandatory_acrs: ["loa2", "loa3"],
      auth_time_required: true
    }

    id_token = signed_id_token(op, client, auth_time: now(), acr: "loa2")

    assert {:ok, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with invalid signature is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with invalid encryption is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = " eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with missing issuer is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, iss: nil)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with missing sub is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, sub: nil)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with missing aud is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, aud: nil)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with missing exp is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, exp: nil)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with missing iat is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, iat: nil)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with invalid issuer is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, iss: "https://wrong.com")

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token with invalid audience is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, aud: "another_client")

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token is expired and is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op
    }

    id_token = signed_id_token(op, client, exp: now() - 1)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token was issued to far in the past and is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      id_token_iat_max_time_gap: 30
    }

    id_token = signed_id_token(op, client, iat: now() - 31)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token nonce doesn't match and is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      nonce: "some another nonce"
    }

    id_token = signed_id_token(op, client, nonce: "some nonce")

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token is absent althouth required, and is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      mandatory_acrs: ["loa2", "loa3"]
    }

    id_token = signed_id_token(op, client)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token ACR is not acceptable and is rejected", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      mandatory_acrs: ["loa2", "loa3"]
    }

    id_token = signed_id_token(op, client, acr: "loa1")

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  test "ID token auth_time is absent although required", %{client: client, op: op} do
    verification_data = %{
      issuer: op["issuer"],
      client_id: client["client_id"],
      server_metadata: op,
      auth_time_required: true
    }

    id_token = signed_id_token(op, client)

    assert {:error, _} = IDToken.verify(id_token, client, verification_data)
  end

  defp signed_id_token(op_metadata, client_conf, claims \\ []) do
    claims_serialized =
      [
        iss: op_metadata["issuer"],
        sub: "user_1",
        aud: client_conf["client_id"],
        exp: now() + 30,
        iat: now()
      ]
      |> Keyword.merge(claims)
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.filter(fn {_k, v} -> v != [] end)
      |> Enum.into(%{})
      |> Jason.encode!()

    jwk =
      op_metadata["jwks"]["keys"]
      |> List.first()
      |> JOSE.JWK.from_map()

    JOSE.JWS.sign(jwk, claims_serialized, %{"alg" => "ES256"})
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp encrypt(signed_id_token, client_conf) do
    jwk = client_conf["jwks"]["keys"] |> List.first() |> JOSE.JWK.from_map()

    JOSE.JWE.block_encrypt(jwk, signed_id_token, %{"alg" => "dir", "enc" => "A128CBC-HS256"})
    |> JOSE.JWE.compact()
    |> elem(1)
  end

  def client_conf() do
    %{
      "client_id" => "client_1",
      "id_token_signed_response_alg" => "ES256",
      "id_token_encrypted_response_alg" => "dir",
      "jwks" => %{
        "keys" => [
          %{"k" => "STlqtIOhWJjoVnYjUjxFLZ6oN1oB70QARGSTWQ_5XgM", "kty" => "oct"}
        ]
      }
    }
  end

  defp op_metadata() do
    %{
      "issuer" => "https://example.com",
      "jwks" => %{
        "keys" => [
          %{
            "crv" => "P-256",
            "d" => "bZa5NEa3OuDAxNs5LvpwPsYHBj0Tmkhr_dzynwUsarI",
            "kty" => "EC",
            "x" => "OpLxw9HqCn50523Rg6s59yE089s7f89HpAgMe9bn6RU",
            "y" => "nzMjJbOdAHQOVIT9KJXJCve_SVRC_3hIvmaX-fnze5g"
          }
        ]
      }
    }
  end

  defp now() do
    System.system_time(:second)
  end
end
