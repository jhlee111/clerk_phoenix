defmodule ClerkPhoenix.Session do
  @moduledoc """
  Authentication session management for ClerkPhoenix.

  This module handles session storage, retrieval, and lifecycle management
  for authentication state and identity data in Phoenix sessions. It focuses
  purely on authentication concerns without user management assumptions.

  Features:
  - Session token extraction from multiple sources
  - Identity data storage with size optimization
  - Authentication session lifecycle tracking
  - Security integration with fingerprinting
  - Session size monitoring and warnings
  """
  require Logger

  import Plug.Conn

  @session_key :clerk_identity
  @large_token_key :clerk_token_large
  @session_metadata_key :clerk_session_meta

  @doc """
  Checks if the connection has an active Clerk session.
  """
  def has_clerk_session?(conn) do
    get_session(conn, @session_key) != nil
  end

  @doc """
  Gets the session token from various sources in the connection.

  This function checks multiple sources for the session token:
  1. __session cookie (standard Clerk cookie)
  2. Phoenix session storage
  3. Authorization header (for API requests)

  Returns the first token found or nil if none exists.
  """
  def get_session_token(conn) do
    Logger.debug("=== get_session_token START ===")

    cond do
      # Check for __session cookie (Clerk's standard cookie)
      session_cookie = get_session_cookie(conn) ->
        Logger.debug("found session cookie")
        session_cookie

      # Check Phoenix session storage
      session_data = get_session(conn, @session_key) ->
        Logger.debug("found phoenix session with #{@session_key}")
        token = extract_token_from_session(session_data)
        token

      # Check Authorization header for API requests
      auth_header = get_auth_header(conn) ->
        Logger.debug("found auth header")
        token = extract_bearer_token(auth_header)
        token

      true ->
        Logger.debug("No session token found")
        nil
    end
  end

  @doc """
  Stores Clerk identity data in the Phoenix session with metadata tracking.
  """
  def put_clerk_identity(conn, identity_data) do
    # Store identity data
    conn_with_identity = put_session(conn, @session_key, identity_data)

    # Store session metadata for tracking
    metadata = %{
      created_at: System.system_time(:second),
      last_accessed: System.system_time(:second),
      subject: get_subject_from_identity(identity_data),
      session_size: estimate_data_size(identity_data)
    }

    conn_with_meta = put_session(conn_with_identity, @session_metadata_key, metadata)

    # Log session creation
    Logger.debug("Auth event: session_created", %{
      subject: metadata.subject,
      session_size: metadata.session_size,
      ip_address: get_client_ip(conn_with_meta)
    })

    conn_with_meta
  end

  @doc """
  Gets Clerk identity data from the Phoenix session and updates access time.
  """
  def get_clerk_identity(conn) do
    case get_session(conn, @session_key) do
      nil -> nil
      identity_data ->
        # Update last accessed time
        update_session_access_time(conn)
        identity_data
    end
  end

  @doc """
  Deletes Clerk identity data from the Phoenix session with cleanup.
  """
  def delete_clerk_identity(conn) do
    # Get identity info for logging before deletion
    identity_data = get_session(conn, @session_key)
    metadata = get_session(conn, @session_metadata_key)

    # Log session deletion
    if identity_data do
      Logger.debug("Auth event: session_deleted", %{
        subject: get_subject_from_identity(identity_data),
        session_duration: calculate_session_duration(metadata),
        ip_address: get_client_ip(conn)
      })
    end

    conn
    |> delete_session(@session_key)
    |> delete_session(@session_metadata_key)
    |> delete_session(@large_token_key)
  end

  @doc """
  Sets a flag indicating that the user's token was too large for cookie storage.
  """
  def put_large_token_flag(conn) do
    put_session(conn, @large_token_key, true)
  end

  @doc """
  Removes the large token flag from the session.
  """
  def delete_large_token_flag(conn) do
    delete_session(conn, @large_token_key)
  end

  @doc """
  Checks if the large token flag is set.
  """
  def has_large_token_flag?(conn) do
    get_session(conn, @large_token_key) == true
  end

  @doc """
  Clears all session data related to authentication.
  """
  def clear_session(conn) do
    delete_clerk_identity(conn)
  end

  @doc """
  Gets session metadata for monitoring and security purposes.
  """
  def get_session_metadata(conn) do
    get_session(conn, @session_metadata_key)
  end

  @doc """
  Updates session metadata with current access information.
  """
  def update_session_metadata(conn, updates) when is_map(updates) do
    current_metadata = get_session(conn, @session_metadata_key) || %{}
    updated_metadata = Map.merge(current_metadata, updates)
    put_session(conn, @session_metadata_key, updated_metadata)
  end

  @doc """
  Estimates the current session size for monitoring cookie limits.

  This function calculates the approximate size of the current session
  data to help prevent exceeding the 4KB cookie limit.
  """
  def estimate_session_size(conn) do
    session_data = get_session(conn) || %{}
    estimate_data_size(session_data)
  end

  @doc """
  Checks if adding data would exceed the session size limit.

  ## Parameters

  - `conn` - The connection
  - `additional_data` - Data to be added to the session
  - `max_size` - Maximum allowed size (default: 3000 bytes)

  Returns true if adding the data would exceed the limit.
  """
  def would_exceed_size_limit?(conn, additional_data, max_size \\ 3000) do
    current_size = estimate_session_size(conn)
    additional_size = estimate_data_size(additional_data)

    current_size + additional_size > max_size
  end

  @doc """
  Validates session integrity and freshness.
  """
  def validate_session_integrity(conn) do
    metadata = get_session_metadata(conn)

    cond do
      is_nil(metadata) ->
        {:error, :missing_metadata}

      session_expired?(metadata) ->
        {:error, :session_expired}

      session_too_old?(metadata) ->
        {:error, :session_too_old}

      true ->
        :ok
    end
  end

  @doc """
  Refreshes session data to extend its lifetime.
  """
  def refresh_session(conn) do
    case get_session_metadata(conn) do
      nil -> conn
      metadata ->
        updated_metadata = %{metadata |
          last_accessed: System.system_time(:second),
          refresh_count: Map.get(metadata, :refresh_count, 0) + 1
        }
        put_session(conn, @session_metadata_key, updated_metadata)
    end
  end

  @doc """
  Clears all session data and resets the session completely.
  """
  def clear_all_session_data(conn) do
    # Log session clear
    identity_data = get_session(conn, @session_key)
    if identity_data do
      Logger.debug("Auth event: session_cleared", %{
        subject: get_subject_from_identity(identity_data),
        ip_address: get_client_ip(conn)
      })
    end

    configure_session(conn, drop: true)
  end

  # Private functions

  defp get_session_cookie(conn) do
    case get_req_header(conn, "cookie") do
      [] -> nil
      headers ->
        headers
        |> Enum.join("; ")
        |> parse_cookies()
        |> Map.get("__session")
    end
  end

  defp parse_cookies(cookie_string) do
    cookie_string
    |> String.split("; ")
    |> Enum.reduce(%{}, fn cookie_pair, acc ->
      case String.split(cookie_pair, "=", parts: 2) do
        [key, value] -> Map.put(acc, String.trim(key), String.trim(value))
        _ -> acc
      end
    end)
  end

  defp extract_token_from_session(session_data) when is_map(session_data) do
    # Session data might contain the token directly or identity info
    cond do
      token = session_data["session_token"] -> token
      token = session_data["token"] -> token
      # If session contains identity data but no direct token, it means
      # we're storing compact identity info instead of the raw token
      session_data["sub"] -> nil
      true -> nil
    end
  end

  defp extract_token_from_session(_), do: nil

  defp get_auth_header(conn) do
    case get_req_header(conn, "authorization") do
      [header] -> header
      _ -> nil
    end
  end

  defp extract_bearer_token("Bearer " <> token), do: String.trim(token)
  defp extract_bearer_token(_), do: nil

  defp get_subject_from_identity(identity_data) when is_map(identity_data) do
    identity_data["sub"] || identity_data[:sub] || identity_data["id"] || identity_data[:id] || "unknown"
  end
  defp get_subject_from_identity(_), do: "unknown"

  defp estimate_data_size(data) do
    try do
      data
      |> JSON.encode!()
      |> byte_size()
    rescue
      _ -> 0
    end
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded_ips] ->
        forwarded_ips
        |> String.split(",")
        |> List.first()
        |> String.trim()
      [] ->
        case get_req_header(conn, "x-real-ip") do
          [real_ip] -> real_ip
          [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
        end
    end
  end

  defp update_session_access_time(conn) do
    case get_session(conn, @session_metadata_key) do
      nil -> conn
      metadata ->
        updated_metadata = %{metadata | last_accessed: System.system_time(:second)}
        put_session(conn, @session_metadata_key, updated_metadata)
    end
  end

  defp calculate_session_duration(nil), do: 0
  defp calculate_session_duration(metadata) do
    current_time = System.system_time(:second)
    created_at = Map.get(metadata, :created_at, current_time)
    current_time - created_at
  end

  defp session_expired?(metadata) do
    max_age = 24 * 60 * 60  # 24 hours
    current_time = System.system_time(:second)
    created_at = Map.get(metadata, :created_at, current_time)

    current_time - created_at > max_age
  end

  defp session_too_old?(metadata) do
    max_idle = 4 * 60 * 60  # 4 hours idle
    current_time = System.system_time(:second)
    last_accessed = Map.get(metadata, :last_accessed, current_time)

    current_time - last_accessed > max_idle
  end
end
