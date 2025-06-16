defmodule ClerkPhoenix.Auth do
  @moduledoc """
  Core authentication module for ClerkPhoenix.

  This module handles the authentication flow without making assumptions about
  user data or user management. It focuses purely on:
  - Token validation and verification
  - Identity extraction from tokens
  - Authentication context creation
  - Session authentication flows

  This module does NOT handle user management, user models, or user business logic.
  Applications are responsible for fetching and managing user data based on the
  identity information returned by this module.
  """

  alias ClerkPhoenix.Token
  alias ClerkPhoenix.Identity
  alias ClerkPhoenix.AuthContext

  require Logger

  @doc """
  Authenticates a request using Clerk session data.

  This function handles both development handshake authentication and
  production session token authentication. It returns identity claims and
  authentication context without making assumptions about user data structure.

  ## Parameters
  - `params` - Request parameters (may contain handshake data)
  - `otp_app` - OTP application for configuration
  - `opts` - Additional options (should include :conn)
  - `session_token` - Session token from cookies/headers

  ## Returns
  - `{:ok, identity, auth_context, claims}` - Successful authentication
  - `{:error, reason}` - Authentication failed

  ## Examples

      iex> ClerkPhoenix.Auth.authenticate(%{"__clerk_handshake" => "eyJ..."}, :my_app, opts)
      {:ok, %{"sub" => "user_123", "email" => "user@example.com"}, auth_context, claims}

      iex> ClerkPhoenix.Auth.authenticate(%{}, :my_app, opts, "session_token")
      {:ok, %{"sub" => "user_123", "email" => "user@example.com"}, auth_context, claims}

      iex> ClerkPhoenix.Auth.authenticate(%{}, :my_app, opts, nil)
      {:error, :no_token}
  """
  def authenticate(params, otp_app, opts \\ [], session_token \\ nil) do
    cond do
      # Development: Check for handshake parameter first
      handshake = params["__clerk_handshake"] ->
        process_handshake(handshake, otp_app, opts)

      # Production/Development: Check for session token
      session_token && is_binary(session_token) ->
        verify_session_token(session_token, otp_app, opts)

      true ->
        {:error, :no_token}
    end
  end

  @doc """
  Processes a Clerk handshake parameter for development environments.

  The handshake mechanism is used in development when Clerk cannot set
  cookies directly due to cross-domain restrictions.
  """
  def process_handshake(handshake_data, otp_app, opts) when is_binary(handshake_data) do
    try do
      case Token.decode_handshake(handshake_data) do
        {:ok, decoded_data} ->
          case extract_session_from_handshake(decoded_data) do
            {:ok, session_token} ->
              verify_session_token(session_token, otp_app, Keyword.put(opts, :from_handshake, true))
            {:error, reason} ->
              {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e ->
        Logger.error("Handshake processing failed: #{inspect(e)}")
        {:error, :handshake_decode_error}
    end
  end

  @doc """
  Verifies a session token using Clerk's JWKS endpoint or API fallback.

  This function first attempts to verify the JWT token locally using Clerk's
  public keys, then falls back to the session verification API if needed.

  Returns identity claims, authentication context, and optionally original JWT claims.
  """
  def verify_session_token(token, otp_app, opts) when is_binary(token) do
    conn = Keyword.get(opts, :conn)
    
    if is_jwt_token?(token) do
      Logger.debug("Token looks like JWT, attempting JWT verification: #{String.slice(token, 0, 20)}...")
      # Token looks like JWT - try JWT verification first
      case Token.verify_jwt_with_jwks(token, otp_app, opts) do
        {:ok, claims} ->
          with {:ok, identity} <- Identity.extract_from_claims(claims, otp_app),
               {:ok, auth_context} <- AuthContext.create_from_claims(claims, conn, opts) do
            {:ok, identity, auth_context, claims}
          else
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          Logger.info("JWT verification failed, falling back to API verification",
            token_preview: String.slice(token, 0, 20) <> "...",
            jwt_failure_reason: reason,
            fallback_to: "session_api"
          )
          # Fallback to session verification endpoint
          verify_session_with_api(token, otp_app, opts)
      end
    else
      Logger.debug("Token looks like session ID, using API verification: #{token}")
      # Token doesn't look like JWT (probably session ID) - use API verification
      verify_session_with_api(token, otp_app, opts)
    end
  end

  # Helper function to detect if a token is a JWT
  defp is_jwt_token?(token) when is_binary(token) do
    # JWT tokens have exactly 3 parts separated by dots
    case String.split(token, ".") do
      [_header, _payload, _signature] -> true
      _ -> false
    end
  end

  @doc """
  Verifies a session token using Clerk's session verification API.

  This is used as a fallback when JWT verification fails or when we need
  to verify session tokens that are not standard JWTs.
  """
  def verify_session_with_api(token, otp_app, opts) do
    token_preview = String.slice(token, 0, 20) <> "..."
    Logger.debug("Attempting API session verification for token: #{token_preview}")
    conn = Keyword.get(opts, :conn)

    case Token.verify_session_with_api(token, otp_app, opts) do
      {:ok, session_data} ->
        Logger.debug("API session verification successful for token: #{token_preview}")
        
        # Extract identity from API session data
        identity = extract_identity_from_session_data(session_data, otp_app)
        
        # Create auth context from session data
        case AuthContext.create_from_session(session_data, conn, opts) do
          {:ok, auth_context} ->
            {:ok, identity, auth_context, nil}  # No JWT claims from API
          {:error, reason} ->
            {:error, reason}
        end

      {:error, :session_expired} ->
        Logger.warning("API session verification failed: Session expired (410)",
          token_preview: token_preview,
          reason: :session_expired
        )
        {:error, :session_expired}

      {:error, reason} ->
        Logger.warning("API session verification failed",
          token_preview: token_preview,
          reason: reason
        )
        {:error, reason}
    end
  end

  @doc """
  Extracts session token from handshake data.

  The handshake contains encoded session information that needs to be
  extracted and processed.
  """
  def extract_session_from_handshake(decoded_data) when is_map(decoded_data) do
    cond do
      session_token = decoded_data["session_token"] ->
        {:ok, session_token}

      session_token = decoded_data[:session_token] ->
        {:ok, session_token}

      # Try to extract from nested structures
      session_data = decoded_data["session"] ->
        case session_data do
          %{"token" => token} -> {:ok, token}
          %{token: token} -> {:ok, token}
          _ -> {:error, :no_session_token_in_handshake}
        end

      true ->
        {:error, :no_session_token_in_handshake}
    end
  end

  # Private helper to extract identity from session API data
  defp extract_identity_from_session_data(session_data, otp_app) do
    # Session API returns user data in a different format than JWT claims
    # We need to transform it to a consistent identity format
    user_data = session_data["user"] || session_data
    
    _config = ClerkPhoenix.Config.get_config(otp_app)
    # Note: Identity mapping could be used here for custom extraction in the future

    %{
      "sub" => user_data["id"],
      "email" => extract_email_from_user_data(user_data),
      "name" => construct_name_from_user_data(user_data),
      "image_url" => user_data["image_url"],
      "organizations" => user_data["organizations"] || []
    }
    |> filter_nil_values()
  end

  defp extract_email_from_user_data(user_data) do
    cond do
      email = user_data["email"] -> email
      email_addresses = user_data["email_addresses"] ->
        case Enum.find(email_addresses, & &1["primary"]) do
          %{"email_address" => email} -> email
          _ -> nil
        end
      true -> nil
    end
  end

  defp construct_name_from_user_data(user_data) do
    first = user_data["first_name"]
    last = user_data["last_name"]
    
    cond do
      is_binary(first) and is_binary(last) -> "#{first} #{last}" |> String.trim()
      is_binary(first) -> first
      is_binary(last) -> last
      true -> nil
    end
  end

  defp filter_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end