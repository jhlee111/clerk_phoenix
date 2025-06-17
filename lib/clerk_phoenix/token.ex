defmodule ClerkPhoenix.Token do
  @moduledoc """
  Token verification and JWT handling for Clerk authentication.

  This module handles JWT token verification using Clerk's JWKS endpoint,
  session token processing, and handshake decoding for development environments.
  """

  require Logger

  @doc """
  Verifies a JWT token using Clerk's JWKS endpoint.

  This is the preferred method for token verification as it validates
  the token cryptographically without requiring an API call.
  """
  def verify_jwt_with_jwks(token, otp_app, opts \\ []) do
    case ClerkPhoenix.JWT.validate_token(token, otp_app, opts) do
      {:ok, claims} -> {:ok, claims}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verifies a session token using Clerk's session verification API.

  This is used as a fallback when JWT verification fails or when we need
  to validate sessions that might not be standard JWTs.
  """
  def verify_session_with_api(token, otp_app, opts \\ []) do
    secret_key = 
      Keyword.get(opts, :clerk_secret_key) || 
      ClerkPhoenix.Config.secret_key(otp_app)
    
    api_url = 
      Keyword.get(opts, :clerk_api_url) || 
      ClerkPhoenix.Config.api_url(otp_app)

    url = "#{api_url}/v1/sessions/#{token}/verify"
    headers = [
      {"Authorization", "Bearer #{secret_key}"},
      {"Content-Type", "application/json"},
      {"Clerk-API-Version", "2025-04-10"}
    ]

    case Req.post(url, headers: headers) do
      {:ok, %{status: 200, body: body}} ->
        case body do
          %{"response" => %{"user" => user_data, "session" => session_data}} ->
            formatted_data = format_api_response_as_session(user_data, session_data)
            {:ok, formatted_data}

          %{"user" => user_data, "session" => session_data} ->
            formatted_data = format_api_response_as_session(user_data, session_data)
            {:ok, formatted_data}

          _ ->
            {:error, :invalid_api_response}
        end

      {:ok, %{status: 410, body: body}} ->
        Logger.warning("Clerk API returned 410 Gone - Session/token expired or revoked",
          session_token: String.slice(token, 0, 20) <> "...",
          response_body: inspect(body),
          status: 410
        )
        {:error, :session_expired}

      {:ok, %{status: status, body: body}} when status in [401, 403] ->
        Logger.warning("Clerk API returned unauthorized",
          session_token: String.slice(token, 0, 20) <> "...",
          status: status,
          response_body: inspect(body)
        )
        {:error, :unauthorized}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("Clerk API returned unexpected status",
          session_token: String.slice(token, 0, 20) <> "...",
          status: status,
          response_body: inspect(body)
        )
        {:error, :api_error}

      {:error, reason} ->
        Logger.error("Clerk API request failed: #{inspect(reason)}")
        {:error, :api_request_failed}
    end
  end

  @doc """
  Decodes a Clerk handshake parameter.

  The handshake is typically a base64-encoded JSON payload containing
  session information for development environments.
  """
  def decode_handshake(handshake_data) when is_binary(handshake_data) do
    try do
      # Handshake data might be base64 encoded or URL encoded
      decoded =
        handshake_data
        |> URI.decode()
        |> Base.decode64!(padding: false)

      case JSON.decode(decoded) do
        {:ok, data} -> {:ok, data}
        {:error, _} -> {:error, :invalid_json_in_handshake}
      end
    rescue
      _ ->
        # Try without base64 decoding in case it's already decoded
        case JSON.decode(handshake_data) do
          {:ok, data} -> {:ok, data}
          {:error, _} -> {:error, :handshake_decode_failed}
        end
    end
  end


  # Private functions

  defp format_api_response_as_session(user_data, session_data) do
    # Return raw session data for identity extraction
    %{
      "user" => user_data,
      "session" => session_data,
      "session_id" => session_data["id"]
    }
  end


end