defmodule ClerkPhoenix.Plug.AuthPlug do
  @moduledoc """
  Phoenix plug for Clerk authentication integration.

  This plug handles authentication for Phoenix requests, focusing purely on
  authentication concerns without making assumptions about user management.

  The plug sets these connection assigns:
  - `:authenticated?` - boolean indicating authentication status
  - `:identity` - extracted identity claims from token
  - `:auth_context` - authentication metadata and context
  - `:token_claims` - raw JWT claims (optional, for debugging)

  Applications are responsible for fetching user data based on the identity.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [redirect: 2, put_flash: 3]

  require Logger

  alias ClerkPhoenix.Auth
  alias ClerkPhoenix.Session
  alias ClerkPhoenix.SessionSecurity
  alias ClerkPhoenix.Config

  @behaviour Plug

  @doc """
  Initializes the plug with different authentication modes.

  ## Options

  - `:require_auth` - Requires authentication, redirects on failure
  - `opts` when is_list - Optional authentication with custom options

  ## Examples

      # Require authentication
      plug ClerkPhoenix.Plug.AuthPlug, :require_auth

      # Optional authentication with custom redirect
      plug ClerkPhoenix.Plug.AuthPlug, redirect_path: "/login"

      # Optional authentication (default)
      plug ClerkPhoenix.Plug.AuthPlug, otp_app: :my_app
  """
  def init(:require_auth) do
    [
      on_auth_failure: :redirect,
      mode: :require_auth
    ]
  end

  def init(opts) when is_list(opts) do
    Keyword.merge([
      on_auth_failure: :redirect,
      mode: :optional
    ], opts)
  end

  @doc """
  Main plug function that handles authentication for requests.

  This function:
  1. Validates session security (fingerprinting, tampering, etc.)
  2. Attempts to authenticate the request using handshake or session data
  3. Sets connection assigns for identity, auth context, and authentication status
  4. Handles authentication failures based on the configured mode

  ## Configuration

  The plug expects the OTP app to be configured. You can specify it using:

  - `:otp_app` option in the plug initialization
  - The plug will attempt to detect it from the connection
  """
  def call(conn, opts) do
    Logger.debug("=== ClerkPhoenix.AuthPlug.call START ===")

    otp_app = get_otp_app(conn, opts)
    mode = Keyword.get(opts, :mode, :optional)

    # Apply session security validation for existing sessions
    conn = if Session.has_clerk_session?(conn) do
      case SessionSecurity.validate_session_security(conn, otp_app) do
        %Plug.Conn{halted: true} = halted_conn -> halted_conn
        validated_conn -> validated_conn
      end
    else
      conn
    end

    # Early return if connection was halted by security validation
    if conn.halted do
      conn
    else
      # Get session token from various sources
      session_token = Session.get_session_token(conn)

      # Add conn to opts for Auth module
      auth_opts = Keyword.put(opts, :conn, conn)

      case Auth.authenticate(conn.params, otp_app, auth_opts, session_token) do
        {:ok, identity, auth_context, original_claims} ->
          Logger.debug("Authentication SUCCESS")
          handle_successful_auth(conn, identity, auth_context, original_claims, otp_app, opts)

        {:error, reason} ->
          Logger.debug("Authentication FAILED: #{inspect(reason)}")

          # Log failed authentication attempt
          if session_token do
            Logger.warning("Authentication failed", %{
              reason: reason,
              ip: get_client_ip(conn),
              user_agent: get_user_agent(conn),
              session_token_preview: String.slice(session_token, 0, 20) <> "..."
            })
          end

          case mode do
            :require_auth ->
              Logger.debug("Handling auth failure with redirect")
              handle_auth_failure(conn, otp_app, opts, reason)
            _ ->
              Logger.debug("Optional auth - setting nil assigns")
              # Optional auth - continue without authentication for ANY failure reason
              # Clear session data if it was expired, but don't redirect
              conn_with_clean_session = if reason == :session_expired do
                Logger.info("Session expired in optional auth mode, clearing session silently")
                configure_session(conn, drop: true)
              else
                conn
              end
              
              conn_with_clean_session
              |> assign(:authenticated?, false)
              |> assign(:identity, nil)
              |> assign(:auth_context, nil)
              |> assign(:token_claims, nil)
          end
      end
    end
  end

  @doc """
  Handles authentication failures based on the configured failure mode.

  ## Failure Modes

  - `:redirect` - Redirects to sign-in page with flash message
  - `:json` - Returns JSON error response
  - `:pass_through` - Continues without authentication (sets assigns to nil/false)
  """
  def handle_auth_failure(conn, otp_app, opts, reason) do
    Logger.debug("Authentication failed: #{inspect(reason)}")

    case Keyword.get(opts, :on_auth_failure, :redirect) do
      :redirect ->
        redirect_path = Keyword.get(opts, :redirect_path, Config.sign_in_url(otp_app))

        # Use different messages based on the failure reason
        {flash_type, message} = case reason do
          :session_expired ->
            {:info, Config.session_expired_message(otp_app)}
          :token_expired ->
            {:info, Config.session_expired_message(otp_app)}
          _ ->
            {:error, Config.auth_required_message(otp_app)}
        end

        conn
        |> configure_session(drop: true)  # Clear stale session
        |> put_flash(flash_type, message)
        |> redirect(to: redirect_path)
        |> halt()

      :json ->
        status = case reason do
          :session_expired -> :unauthorized
          :token_expired -> :unauthorized
          _ -> :unauthorized
        end

        error_message = Config.auth_required_json_message(otp_app)

        conn
        |> put_status(status)
        |> Phoenix.Controller.json(%{error: error_message})
        |> halt()

      :pass_through ->
        conn
        |> assign(:authenticated?, false)
        |> assign(:identity, nil)
        |> assign(:auth_context, nil)
        |> assign(:token_claims, nil)
    end
  end

  @doc """
  Helper function to check if a connection is authenticated.
  """
  def authenticated?(conn) do
    conn.assigns[:authenticated?] == true
  end

  @doc """
  Helper function to get the identity from connection assigns.
  """
  def identity(conn) do
    conn.assigns[:identity]
  end

  @doc """
  Helper function to get the authentication context from connection assigns.
  """
  def auth_context(conn) do
    conn.assigns[:auth_context]
  end

  @doc """
  Helper function to get the raw JWT claims from connection assigns.
  """
  def token_claims(conn) do
    conn.assigns[:token_claims]
  end

  @doc """
  Helper function to require authentication for a connection.

  This can be used in controllers for conditional authentication checks.
  """
  def require_auth(conn, opts \\ []) do
    if authenticated?(conn) do
      conn
    else
      otp_app = get_otp_app(conn, opts)
      handle_auth_failure(conn, otp_app, opts, :not_authenticated)
    end
  end

  @doc """
  Helper function to logout and clean up session data.
  """
  def logout(conn, opts \\ []) do
    otp_app = get_otp_app(conn, opts)

    # Get identity for logging before cleanup
    identity = identity(conn)
    subject = if identity, do: identity["sub"], else: nil

    # Log logout activity if we have identity
    if subject do
      Logger.info("User logged out", subject: subject, ip: get_client_ip(conn))
    end

    # Clear session data
    conn
    |> Session.clear_session()
    |> assign(:authenticated?, false)
    |> assign(:identity, nil)
    |> assign(:auth_context, nil)
    |> assign(:token_claims, nil)
    |> put_flash(:info, "You have been signed out successfully.")
    |> redirect(to: Config.after_sign_out_url(otp_app))
    |> halt()
  end

  # Private functions

  defp get_otp_app(conn, opts) do
    cond do
      otp_app = Keyword.get(opts, :otp_app) -> otp_app
      otp_app = conn.private[:phoenix_endpoint] ->
        # Extract OTP app from Phoenix endpoint module name
        # MyAppWeb.Endpoint -> :my_app
        otp_app
        |> Module.split()
        |> List.first()
        |> Macro.underscore()
        |> String.to_atom()
      true ->
        raise "Could not determine OTP app for ClerkPhoenix configuration. " <>
              "Please specify :otp_app in plug options or ensure Phoenix endpoint is properly configured."
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

  defp get_user_agent(conn) do
    conn
    |> get_req_header("user-agent")
    |> List.first("unknown")
    |> String.slice(0, 200)  # Limit length
  end

  # Helper function to handle successful authentication
  defp handle_successful_auth(conn, identity, auth_context, original_claims, otp_app, opts) do
    # Set connection assigns with new architecture
    conn_with_auth = assign(conn, :authenticated?, true)
    conn_with_identity = assign(conn_with_auth, :identity, identity)
    conn_with_context = assign(conn_with_identity, :auth_context, auth_context)
    conn_with_claims = assign(conn_with_context, :token_claims, original_claims)

    # Create session fingerprint for new sessions
    conn_with_fingerprint = if Session.has_clerk_session?(conn_with_claims) do
      conn_with_claims
    else
      SessionSecurity.create_session_fingerprint(conn_with_claims, otp_app)
    end

    # Store identity in session (compact format)
    result_conn = store_identity_session(conn_with_fingerprint, identity, otp_app, opts)

    Logger.debug("=== ClerkPhoenix.AuthPlug.call SUCCESS END ===")
    result_conn
  end

  # Store identity data in session (replacing the old user data storage)
  defp store_identity_session(conn, identity, _otp_app, opts) do
    Logger.debug("=== store_identity_session START ===")

    max_session_size = Keyword.get(opts, :max_session_size, 3000)

    # Create compact identity data for session storage
    compact_identity = create_compact_identity(identity, max_session_size)

    conn_with_identity = Session.put_clerk_identity(conn, compact_identity)
    final_conn = Session.delete_large_token_flag(conn_with_identity)
    
    Logger.debug("=== store_identity_session END ===")
    final_conn
  end

  # Create compact identity suitable for session storage
  defp create_compact_identity(identity, max_session_size) do
    # Start with essential identity fields
    compact_identity = %{
      "sub" => identity["sub"],
      "email" => identity["email"],
      "name" => identity["name"]
    }
    |> filter_nil_values()

    # Check if it fits in the size limit
    identity_size = estimate_identity_size(compact_identity)

    if identity_size <= max_session_size do
      # Add more fields if we have space
      Map.merge(compact_identity, %{
        "image_url" => identity["image_url"],
        "organizations" => identity["organizations"]
      })
      |> filter_nil_values()
    else
      # Keep only essential fields
      compact_identity
    end
  end

  defp estimate_identity_size(identity) do
    identity
    |> Jason.encode!()
    |> byte_size()
  end

  defp filter_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end