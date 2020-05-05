defmodule OIDCTest.Support.Helpers do
  def signed_id_token(op_metadata, client_conf, claims \\ []) do
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

  def get(_), do: client_conf()

  def client_conf() do
    %{
      "client_id" => "client_1",
      "client_secret" => "some secret",
      "id_token_signed_response_alg" => "ES256",
      "id_token_encrypted_response_alg" => "dir",
      "jwks" => %{
        "keys" => [
          %{
            "alg" => "ES256",
            "crv" => "P-256",
            "d" => "54AykmfcfOpgmDT9dIzDuwGlabdzPdh4RFq074rWO6Q",
            "kty" => "EC",
            "x" => "D4GUiB9ja1rQscPT5XiZFjFUjUpTVyHP7WjxvHcIbG4",
            "y" => "c2wJt4S02GMVU-XVILXEAL90PYIxPDC3FNu6o1GLSzY"
          }
        ]
      }
    }
  end

  def op_metadata() do
    %{
      "authorization_endpoint" => "https://example.com/authorize?a=1",
      "issuer" => "https://example.com",
      "jwks" => %{
        "keys" => [
          %{
            "alg" => "ES256",
            "crv" => "P-256",
            "d" => "bZa5NEa3OuDAxNs5LvpwPsYHBj0Tmkhr_dzynwUsarI",
            "kty" => "EC",
            "x" => "OpLxw9HqCn50523Rg6s59yE089s7f89HpAgMe9bn6RU",
            "y" => "nzMjJbOdAHQOVIT9KJXJCve_SVRC_3hIvmaX-fnze5g"
          }
        ]
      },
      "token_endpoint" => "https://example.com/token"
    }
  end

  def now() do
    System.system_time(:second)
  end
end
