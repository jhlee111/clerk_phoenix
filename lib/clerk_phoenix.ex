defmodule ClerkPhoenix do
  @moduledoc """
  ClerkPhoenix provides seamless integration between Clerk authentication and Phoenix applications.

  ## Features

  - **JWT Validation**: Secure JWT token validation using Clerk's JWKS endpoint
  - **Session Management**: Optimized session storage with 4KB cookie limit handling
  - **Authentication Plugs**: Ready-to-use Phoenix plugs for authentication
  - **Development Support**: Handshake flow for development environments
  - **Security Hardening**: Session fingerprinting, rate limiting, and input validation
  - **Error Handling**: Comprehensive error handling with user-friendly messages

  ## Quick Start

  1. Add `clerk_phoenix` to your dependencies in `mix.exs`:

      ```elixir
      def deps do
        [
          {:clerk_phoenix, "~> 0.1.0"}
        ]
      end
      ```

  2. Configure your Clerk settings in `config/runtime.exs`:

      ```elixir
      config :my_app, ClerkPhoenix,
        publishable_key: System.get_env("CLERK_PUBLISHABLE_KEY"),
        secret_key: System.get_env("CLERK_SECRET_KEY"),
        frontend_api_url: System.get_env("CLERK_FRONTEND_API_URL")
      ```

  3. Add authentication to your Phoenix router:

      ```elixir
      defmodule MyAppWeb.Router do
        use MyAppWeb, :router

        pipeline :auth do
          plug ClerkPhoenix.Plug.AuthPlug, :require_auth
        end

        scope "/", MyAppWeb do
          pipe_through [:browser, :auth]

          get "/dashboard", DashboardController, :index
        end
      end
      ```

  ## Configuration

  ClerkPhoenix uses a minimal configuration approach with smart defaults:

  ### Required Environment Variables
  - `CLERK_PUBLISHABLE_KEY` - Your Clerk publishable key
  - `CLERK_SECRET_KEY` - Your Clerk secret key
  - `CLERK_FRONTEND_API_URL` - Your Clerk frontend API URL

  ### Optional Configuration
  All other settings have sensible defaults but can be customized:

      ```elixir
      config :my_app, ClerkPhoenix,
        # Required
        publishable_key: System.get_env("CLERK_PUBLISHABLE_KEY"),
        secret_key: System.get_env("CLERK_SECRET_KEY"),
        frontend_api_url: System.get_env("CLERK_FRONTEND_API_URL"),

        # Optional with defaults
        routes: %{
          sign_in: "/sign-in",
          sign_out: "/sign-out",
          after_sign_in: "/dashboard",
          after_sign_out: "/"
        },
        messages: %{
          auth_required: "Please sign in to continue.",
          session_expired: "Your session has expired. Please sign in again."
        }
      ```

  ## Authentication Modes

  ClerkPhoenix supports different authentication modes:

  - `:require_auth` - Requires authentication, redirects on failure
  - `:optional_auth` - Optional authentication, continues without user
  - Custom options for specific behavior

  ## Security Features

  - **JWT Validation**: Cryptographic verification using Clerk's public keys
  - **Session Security**: Fingerprinting and rotation for session hijacking protection
  - **Token Blacklisting**: Revoked token management
  - **Rate Limiting**: Protection against brute force attacks
  - **Input Validation**: XSS and SQL injection protection

  ## Frontend Integration

  ClerkPhoenix automatically configures Clerk.js on the frontend:

      ```javascript
      // Automatically available in your templates
      window.clerkConfig = {
        publishableKey: "pk_...",
        frontendApiUrl: "https://...",
        routes: {...}
      };
      ```

  ## Error Handling

  ClerkPhoenix provides comprehensive error handling:

  - **Token Expiration**: Automatic detection and user-friendly messages
  - **API Failures**: Graceful fallback with detailed logging
  - **Session Issues**: Clear session cleanup and redirect handling

  See the individual modules for detailed documentation:

  - `ClerkPhoenix.Auth` - Core authentication logic
  - `ClerkPhoenix.Plug.AuthPlug` - Phoenix authentication plug
  - `ClerkPhoenix.JWT` - JWT validation and processing
  - `ClerkPhoenix.Config` - Configuration helpers
  """

  @doc """
  Returns the current version of ClerkPhoenix.
  """
  def version, do: "0.1.0"

  @doc """
  Validates that all required configuration is present.

  ## Examples

      iex> ClerkPhoenix.validate_config!(:my_app)
      :ok
  """
  def validate_config!(otp_app \\ nil) do
    ClerkPhoenix.Config.validate_config!(otp_app)
  end

  @doc """
  Gets configuration for the given OTP app.

  ## Examples

      iex> config = ClerkPhoenix.get_config(:my_app)
      iex> config.publishable_key
      "pk_test"
      iex> config.secret_key
      "sk_test"
  """
  def get_config(otp_app) do
    ClerkPhoenix.Config.get_config(otp_app)
  end

  @doc """
  Hello function for testing.

  ## Examples

      iex> ClerkPhoenix.hello()
      :world
  """
  def hello do
    :world
  end
end
