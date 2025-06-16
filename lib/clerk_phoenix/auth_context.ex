defmodule ClerkPhoenix.AuthContext do
  @moduledoc """
  Authentication context management for ClerkPhoenix.

  This module manages authentication state and metadata throughout the request lifecycle.
  It tracks authentication status, session information, and token metadata without
  making assumptions about user data or business logic.

  The AuthContext is focused purely on authentication concerns:
  - Authentication status and timing
  - Session metadata and security information
  - Token validation metadata
  - Authentication event tracking

  This module does NOT handle user management or user-specific business logic.
  """

  require Logger

  @doc """
  Creates a new authentication context from validated token data.

  ## Parameters
  - `claims` - Validated JWT claims
  - `conn` - Phoenix connection for extracting request metadata
  - `opts` - Additional options

  ## Returns
  - `{:ok, auth_context}` - Successfully created authentication context
  - `{:error, reason}` - Failed to create context

  ## Examples

      iex> ClerkPhoenix.AuthContext.create_from_claims(claims, conn)
      {:ok, %{
        authenticated_at: 1640995200,
        session_id: "sess_123",
        token_type: :jwt,
        issued_at: 1640995200,
        expires_at: 1640998800,
        issuer: "https://clerk.example.com",
        client_ip: "192.168.1.1",
        user_agent: "Mozilla/5.0...",
        request_id: "req_123"
      }}
  """
  def create_from_claims(claims, conn, opts \\ []) do
    try do
      auth_context = %{
        authenticated_at: System.system_time(:second),
        session_id: extract_session_id(claims),
        token_type: :jwt,
        issued_at: claims["iat"],
        expires_at: claims["exp"],
        issuer: claims["iss"],
        audience: claims["aud"] || claims["azp"],
        subject: claims["sub"],
        jti: claims["jti"],
        client_ip: get_client_ip(conn),
        user_agent: get_user_agent(conn),
        request_id: get_request_id(conn),
        authentication_method: :token_validation,
        security_metadata: extract_security_metadata(claims, conn, opts)
      }
      |> filter_nil_values()

      {:ok, auth_context}
    rescue
      error ->
        Logger.error("Failed to create auth context: #{inspect(error)}")
        {:error, :context_creation_failed}
    end
  end

  @doc """
  Creates an authentication context from session data (non-JWT tokens).

  ## Parameters
  - `session_data` - Session data from API verification
  - `conn` - Phoenix connection for extracting request metadata
  - `opts` - Additional options

  ## Returns
  - `{:ok, auth_context}` - Successfully created authentication context
  - `{:error, reason}` - Failed to create context
  """
  def create_from_session(session_data, conn, opts \\ []) do
    try do
      auth_context = %{
        authenticated_at: System.system_time(:second),
        session_id: session_data["session_id"],
        token_type: :session_token,
        issued_at: parse_timestamp(session_data["created_at"]),
        expires_at: parse_timestamp(session_data["expire_at"]),
        subject: session_data["id"],
        client_ip: get_client_ip(conn),
        user_agent: get_user_agent(conn),
        request_id: get_request_id(conn),
        authentication_method: :api_verification,
        security_metadata: extract_security_metadata(session_data, conn, opts)
      }
      |> filter_nil_values()

      {:ok, auth_context}
    rescue
      error ->
        Logger.error("Failed to create session auth context: #{inspect(error)}")
        {:error, :context_creation_failed}
    end
  end

  @doc """
  Validates an authentication context to ensure it's still valid.

  ## Parameters
  - `auth_context` - Authentication context to validate
  - `opts` - Validation options

  ## Returns
  - `:ok` - Context is valid
  - `{:error, reason}` - Context is invalid

  ## Examples

      iex> ClerkPhoenix.AuthContext.validate(auth_context)
      :ok

      iex> ClerkPhoenix.AuthContext.validate(expired_context)
      {:error, :expired}
  """
  def validate(auth_context, opts \\ []) do
    current_time = System.system_time(:second)
    max_age = Keyword.get(opts, :max_age, 24 * 60 * 60)  # 24 hours default

    cond do
      # Check if context is too old
      current_time - auth_context.authenticated_at > max_age ->
        {:error, :context_too_old}

      # Check if token has expired (if we have expiration info)
      auth_context[:expires_at] && current_time > auth_context.expires_at ->
        {:error, :token_expired}

      # Check if authentication happened in the future (clock skew)
      auth_context.authenticated_at > current_time + 300 ->  # 5 minute leeway
        {:error, :invalid_auth_time}

      true ->
        :ok
    end
  end

  @doc """
  Updates authentication context with new information.

  ## Parameters
  - `auth_context` - Existing authentication context
  - `updates` - Map of updates to apply

  ## Returns
  Updated authentication context.
  """
  def update(auth_context, updates) when is_map(updates) do
    Map.merge(auth_context, updates)
  end

  @doc """
  Checks if an authentication context indicates an authenticated session.

  ## Parameters
  - `auth_context` - Authentication context to check

  ## Returns
  - `true` - Context indicates valid authentication
  - `false` - Context does not indicate authentication
  """
  def authenticated?(auth_context) do
    case auth_context do
      %{subject: subject} when is_binary(subject) and subject != "" -> true
      _ -> false
    end
  end

  @doc """
  Gets the time remaining until the authentication expires.

  ## Parameters
  - `auth_context` - Authentication context

  ## Returns
  - Integer seconds until expiration, or `:no_expiration` if no expiry set
  """
  def time_until_expiry(auth_context) do
    case auth_context[:expires_at] do
      nil -> :no_expiration
      expires_at ->
        current_time = System.system_time(:second)
        max(0, expires_at - current_time)
    end
  end

  # Private functions

  defp extract_session_id(claims) do
    claims["sid"] || claims["session_id"] || claims["jti"]
  end

  defp extract_security_metadata(data, conn, opts) do
    %{
      request_path: conn.request_path,
      request_method: conn.method,
      secure_connection: conn.scheme == :https,
      forwarded_for: get_forwarded_for(conn),
      session_fingerprint: Keyword.get(opts, :session_fingerprint),
      authentication_source: determine_auth_source(data, opts)
    }
    |> filter_nil_values()
  end

  defp determine_auth_source(data, opts) do
    cond do
      Keyword.get(opts, :from_handshake) -> :handshake
      Map.has_key?(data, "iat") -> :jwt_token
      true -> :session_api
    end
  end

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded_ips] ->
        forwarded_ips
        |> String.split(",")
        |> List.first()
        |> String.trim()
      [] ->
        case Plug.Conn.get_req_header(conn, "x-real-ip") do
          [real_ip] -> real_ip
          [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
        end
    end
  end

  defp get_forwarded_for(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded] -> forwarded
      [] -> nil
    end
  end

  defp get_user_agent(conn) do
    conn
    |> Plug.Conn.get_req_header("user-agent")
    |> List.first("unknown")
    |> String.slice(0, 200)  # Limit length
  end

  defp get_request_id(conn) do
    case Plug.Conn.get_req_header(conn, "x-request-id") do
      [request_id] -> request_id
      [] -> generate_request_id()
    end
  end

  defp generate_request_id do
    "req_" <> (:crypto.strong_rand_bytes(8) |> Base.encode64() |> String.slice(0, 12))
  end

  defp parse_timestamp(timestamp_string) when is_binary(timestamp_string) do
    case DateTime.from_iso8601(timestamp_string) do
      {:ok, datetime, _} -> DateTime.to_unix(datetime)
      _ -> nil
    end
  end

  defp parse_timestamp(timestamp) when is_integer(timestamp), do: timestamp
  defp parse_timestamp(_), do: nil

  defp filter_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end