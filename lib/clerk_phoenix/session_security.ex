defmodule ClerkPhoenix.SessionSecurity do
  @moduledoc """
  Session security hardening including fingerprinting, rotation, and validation.

  Provides protection against:
  - Session hijacking through fingerprinting
  - Session fixation through rotation
  - Concurrent session abuse through limits
  - Replay attacks through timestamps
  - Session tampering through integrity checks

  This module integrates with ClerkPhoenix.Security.Monitor for comprehensive
  security event logging and analysis.
  """

  require Logger
  import Plug.Conn

  alias ClerkPhoenix.Security.Config
  alias ClerkPhoenix.Session

  @session_fingerprint_key "_clerk_fingerprint"
  @session_created_key "_clerk_created"
  @session_rotated_key "_clerk_rotated"
  @session_tracker_table :clerk_session_tracker

  @doc """
  Creates a secure session fingerprint based on request characteristics.

  The fingerprint is based on:
  - Client IP address
  - User-Agent hash (to prevent bloat)
  - Accept-Language header (first 50 chars)

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.create_session_fingerprint(conn)
      %Plug.Conn{...}
  """
  def create_session_fingerprint(conn, otp_app \\ nil) do
    if Config.session_fingerprint_enabled?(otp_app || get_otp_app(conn)) do
      fingerprint = generate_current_fingerprint(conn)
      current_time = System.system_time(:second)

      conn
      |> put_session(@session_fingerprint_key, fingerprint)
      |> put_session(@session_created_key, current_time)
      |> put_session(@session_rotated_key, current_time)
      |> tap(fn _ ->
        Logger.debug("Session fingerprint created", %{
          fingerprint_hash: String.slice(fingerprint, 0, 8),
          ip_address: get_client_ip(conn)
        })
      end)
    else
      conn
    end
  end

  @doc """
  Validates session fingerprint to detect potential hijacking.

  ## Returns
  - `:ok` - Session fingerprint is valid
  - `{:error, reason}` - Session fingerprint validation failed

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.validate_session_fingerprint(conn)
      :ok

      iex> ClerkPhoenix.SessionSecurity.validate_session_fingerprint(conn)
      {:error, :fingerprint_mismatch}
  """
  def validate_session_fingerprint(conn, otp_app \\ nil) do
    otp_app = otp_app || get_otp_app(conn)

    if Config.session_fingerprint_enabled?(otp_app) do
      stored_fingerprint = get_session(conn, @session_fingerprint_key)
      current_fingerprint = generate_current_fingerprint(conn)

      case stored_fingerprint do
        nil ->
          Logger.warning("Missing session fingerprint", session_id: get_session_id(conn))
          {:error, :missing_fingerprint}

        ^current_fingerprint ->
          check_session_age(conn, otp_app)

        _ ->
          Logger.warning("Session fingerprint mismatch - possible hijacking attempt",
            session_id: get_session_id(conn),
            ip: get_client_ip(conn),
            user_agent_hash: get_user_agent_hash(conn)
          )
          Logger.error("Security incident: session_hijacking_attempt", %{
            session_id: get_session_id(conn),
            ip_address: get_client_ip(conn),
            stored_fingerprint: String.slice(stored_fingerprint, 0, 8),
            current_fingerprint: String.slice(current_fingerprint, 0, 8)
          })
          {:error, :fingerprint_mismatch}
      end
    else
      # Fingerprinting disabled, just check session age
      check_session_age(conn, otp_app)
    end
  end

  @doc """
  Rotates session identifier and updates fingerprint if needed.

  Session rotation helps prevent session fixation attacks by periodically
  changing the session identifier.

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.rotate_session_if_needed(conn)
      %Plug.Conn{...}
  """
  def rotate_session_if_needed(conn, otp_app \\ nil) do
    otp_app = otp_app || get_otp_app(conn)
    session_rotated = get_session(conn, @session_rotated_key)
    current_time = System.system_time(:second)
    rotation_interval = Config.get(otp_app, [:session_security, :rotation_interval]) || (4 * 60 * 60)

    if should_rotate_session?(session_rotated, current_time, rotation_interval) do
      Logger.info("Rotating session for security", session_id: get_session_id(conn))

      Logger.debug("Auth event: session_rotated", %{
        session_id: get_session_id(conn),
        ip_address: get_client_ip(conn),
        rotation_reason: :scheduled
      })

      conn
      |> configure_session(renew: true)
      |> put_session(@session_rotated_key, current_time)
      |> create_session_fingerprint(otp_app)
    else
      conn
    end
  end

  @doc """
  Invalidates all sessions for a user (for logout or security breach).

  This is useful when:
  - User logs out from all devices
  - Security breach is detected
  - Password is changed
  - Account is compromised

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.invalidate_user_sessions("user_123")
      :ok
  """
  def invalidate_user_sessions(user_id) do
    # Add user_id to token blacklist to invalidate all sessions
    ClerkPhoenix.TokenBlacklist.blacklist_token("user_sessions:#{user_id}")

    # Remove from concurrent session tracking
    remove_all_user_sessions(user_id)

    Logger.error("Security incident: user_sessions_invalidated", %{
      user_id: user_id,
      invalidation_reason: :security_action
    })

    Logger.info("Invalidated all sessions for user", user_id: user_id)
    :ok
  end

  @doc """
  Checks if user has too many concurrent sessions.

  This helps prevent account sharing and unauthorized access by limiting
  the number of simultaneous sessions per user.

  ## Parameters
  - `conn` - The connection
  - `user_id` - The user identifier
  - `otp_app` - The OTP application (optional)

  ## Returns
  - `:ok` - Session count is within limits
  - `{:error, :too_many_sessions}` - Too many concurrent sessions

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.check_concurrent_sessions(conn, "user_123")
      :ok

      iex> ClerkPhoenix.SessionSecurity.check_concurrent_sessions(conn, "user_123")
      {:error, :too_many_sessions}
  """
  def check_concurrent_sessions(conn, user_id, otp_app \\ nil) do
    otp_app = otp_app || get_otp_app(conn)
    max_sessions = Config.max_concurrent_sessions(otp_app)

    ensure_session_tracker()

    session_key = "concurrent_sessions:#{user_id}"
    current_session = get_session_id(conn)

    case :ets.lookup(@session_tracker_table, session_key) do
      [{^session_key, sessions}] when length(sessions) >= max_sessions ->
        if current_session in sessions do
          :ok
        else
          Logger.warning("Too many concurrent sessions for user",
            user_id: user_id,
            session_count: length(sessions),
            max_allowed: max_sessions
          )

          Logger.error("Security incident: too_many_concurrent_sessions", %{
            user_id: user_id,
            session_count: length(sessions),
            max_allowed: max_sessions,
            ip_address: get_client_ip(conn)
          })

          {:error, :too_many_sessions}
        end

      [{^session_key, sessions}] ->
        # Add current session if not present
        updated_sessions = [current_session | Enum.take(sessions, max_sessions - 1)]
        :ets.insert(@session_tracker_table, {session_key, updated_sessions})
        :ok

      [] ->
        # First session for this user
        :ets.insert(@session_tracker_table, {session_key, [current_session]})
        :ok
    end
  rescue
    ArgumentError ->
      # ETS table doesn't exist, create it and retry
      ensure_session_tracker()
      check_concurrent_sessions(conn, user_id, otp_app)
  end

  @doc """
  Removes session from concurrent session tracking.

  This should be called when a session ends (logout, expiration, etc.)

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.remove_session_tracking(conn, "user_123")
      :ok
  """
  def remove_session_tracking(conn, user_id) do
    session_key = "concurrent_sessions:#{user_id}"
    current_session = get_session_id(conn)

    case :ets.lookup(@session_tracker_table, session_key) do
      [{^session_key, sessions}] ->
        updated_sessions = List.delete(sessions, current_session)
        if updated_sessions == [] do
          :ets.delete(@session_tracker_table, session_key)
        else
          :ets.insert(@session_tracker_table, {session_key, updated_sessions})
        end

      [] ->
        :ok
    end

    Logger.debug("Auth event: session_tracking_removed", %{
      user_id: user_id,
      session_id: current_session
    })

    :ok
  rescue
    ArgumentError ->
      :ok  # Table doesn't exist, nothing to remove
  end

  @doc """
  Security plug that validates session security requirements.

  This plug should be used in authentication pipelines to ensure
  session security requirements are met.

  ## Examples

      # In your router or controller
      plug ClerkPhoenix.SessionSecurity, :validate_session_security
  """
  def validate_session_security(conn, otp_app \\ nil) do
    otp_app = otp_app || get_otp_app(conn)

    with :ok <- validate_session_fingerprint(conn, otp_app),
         :ok <- check_session_tampering(conn, otp_app),
         :ok <- Session.validate_session_integrity(conn) do
      rotate_session_if_needed(conn, otp_app)
    else
      {:error, reason} ->
        Logger.warning("Session security validation failed",
          reason: reason,
          session_id: get_session_id(conn),
          ip: get_client_ip(conn)
        )

        Logger.error("Security incident: session_security_validation_failed", %{
          reason: reason,
          session_id: get_session_id(conn),
          ip_address: get_client_ip(conn)
        })

        conn
        |> configure_session(drop: true)
        |> put_status(:unauthorized)
        |> Phoenix.Controller.json(%{error: "Session security validation failed"})
        |> halt()
    end
  end

  @doc """
  Gets session security statistics for monitoring.

  ## Examples

      iex> ClerkPhoenix.SessionSecurity.get_session_stats()
      %{
        total_tracked_users: 42,
        total_active_sessions: 156,
        average_sessions_per_user: 3.7
      }
  """
  def get_session_stats do
    ensure_session_tracker()

    all_entries = :ets.tab2list(@session_tracker_table)
    total_users = length(all_entries)
    total_sessions = Enum.reduce(all_entries, 0, fn {_key, sessions}, acc ->
      acc + length(sessions)
    end)

    average_sessions = if total_users > 0, do: total_sessions / total_users, else: 0

    %{
      total_tracked_users: total_users,
      total_active_sessions: total_sessions,
      average_sessions_per_user: Float.round(average_sessions, 1)
    }
  end

  # Private functions

  defp generate_current_fingerprint(conn) do
    components = [
      get_client_ip(conn),
      get_user_agent_hash(conn),
      get_accept_language(conn)
    ]

    components
    |> Enum.join("|")
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode64()
    |> String.slice(0, 32)
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

  defp get_user_agent_hash(conn) do
    conn
    |> get_req_header("user-agent")
    |> List.first("unknown")
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode64()
    |> String.slice(0, 16)
  end

  defp get_accept_language(conn) do
    conn
    |> get_req_header("accept-language")
    |> List.first("")
    |> String.slice(0, 50)  # Limit to prevent bloat
  end

  defp get_session_id(conn) do
    case get_session(conn, "_csrf_token") do
      nil -> "no_session"
      token -> String.slice(token, 0, 8)  # First 8 chars for logging
    end
  end

  defp check_session_age(conn, otp_app) do
    session_created = get_session(conn, @session_created_key)
    current_time = System.system_time(:second)
    max_age = Config.session_timeout_hours(otp_app) * 60 * 60

    case session_created do
      nil ->
        Logger.warning("Missing session creation timestamp")
        {:error, :missing_timestamp}

      created_time when current_time - created_time > max_age ->
        Logger.info("Session expired due to age",
          age_seconds: current_time - created_time,
          session_id: get_session_id(conn)
        )

        Logger.debug("Auth event: session_expired_age", %{
          session_id: get_session_id(conn),
          age_seconds: current_time - created_time,
          max_age_seconds: max_age
        })

        {:error, :session_expired}

      _ ->
        :ok
    end
  end

  defp should_rotate_session?(session_rotated, current_time, rotation_interval) do
    case session_rotated do
      nil -> true  # No rotation timestamp, should rotate
      rotated_time -> current_time - rotated_time > rotation_interval
    end
  end

  defp check_session_tampering(conn, otp_app) do
    session_data = get_session(conn)
    max_keys = Config.get(otp_app, [:session_security, :max_session_keys]) || 50
    max_value_size = Config.get(otp_app, [:session_security, :max_session_value_size]) || 10_000

    cond do
      # Check if session has too many keys
      map_size(session_data) > max_keys ->
        Logger.warning("Session has too many keys - possible tampering",
          key_count: map_size(session_data),
          session_id: get_session_id(conn)
        )

        Logger.error("Security incident: session_tampering_detected", %{
          tampering_type: :too_many_keys,
          key_count: map_size(session_data),
          session_id: get_session_id(conn),
          ip_address: get_client_ip(conn)
        })

        {:error, :session_tampering}

      # Check for suspicious session values
      has_suspicious_values?(session_data, max_value_size) ->
        Logger.warning("Session contains suspicious values",
          session_id: get_session_id(conn)
        )

        Logger.error("Security incident: session_tampering_detected", %{
          tampering_type: :suspicious_values,
          session_id: get_session_id(conn),
          ip_address: get_client_ip(conn)
        })

        {:error, :session_tampering}

      true ->
        :ok
    end
  end

  defp has_suspicious_values?(session_data, max_value_size) do
    Enum.any?(session_data, fn {_key, value} ->
      case value do
        val when is_binary(val) -> String.length(val) > max_value_size
        val when is_list(val) -> length(val) > 1000
        _ -> false
      end
    end)
  end

  defp ensure_session_tracker do
    case :ets.whereis(@session_tracker_table) do
      :undefined ->
        try do
          :ets.new(@session_tracker_table, [:named_table, :public, read_concurrency: true])
        rescue
          ArgumentError ->
            # Table already exists
            :ok
        end
      _ ->
        :ok
    end
  end

  defp remove_all_user_sessions(user_id) do
    session_key = "concurrent_sessions:#{user_id}"
    :ets.delete(@session_tracker_table, session_key)
  rescue
    ArgumentError ->
      :ok  # Table doesn't exist
  end

  defp get_otp_app(conn) do
    case conn.private[:phoenix_endpoint] do
      nil -> :clerk_phoenix  # Default fallback
      endpoint ->
        endpoint
        |> Module.split()
        |> List.first()
        |> Macro.underscore()
        |> String.to_atom()
    end
  end
end
