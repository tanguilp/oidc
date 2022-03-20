defmodule OIDC.Auth.ProtocolError do
  @enforce_keys [:error]

  defexception [:error, :details]

  @type t :: %__MODULE__{
          error: atom(),
          details: any()
        }

  @impl true
  def message(%{error: :missing_response_params}),
    do: "Mandatory response param is missing from OP's response"

  def message(%{error: :missing_client_config}),
    do: "Client configuration could not be retrieve at runtime"

  def message(%{error: :token_endpoint_authenticator_not_found}),
    do: "No client authenticator could be found to request the token endpoint"

  def message(%{error: :token_endpoint_invalid_http_status, details: details}),
    do: "Token endpoint responded with an invalid status (#{details})"

  def message(%{error: :token_endpoint_invalid_http_status}),
    do: "Token endpoint HTTP request failed"

  def message(%{error: :op_response_malformed_scope_param}),
    do: "OP responded with a malformed scope parameter"

  def message(%{error: :token_endpoint_invalid_response}),
    do: "A parameter is missing in token endpoint response"

  def message(%{error: :non_matching_resp_iss_param}),
    do: "Response `iss` parameter does not match requested issuer"

  def message(%{error: :non_matching_resp_iss_param_with_id_token}),
    do: "Response `iss` parameter does not match ID token issuer"
end
