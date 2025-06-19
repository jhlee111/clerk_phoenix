if Code.ensure_loaded?(Phoenix.LiveView) do
  defmodule ClerkPhoenix.LiveView do
    @moduledoc """
    LiveView integration for ClerkPhoenix authentication.

    This module provides `on_mount` hooks that enable authentication in Phoenix LiveView.
    It retrieves authentication data from the session that was set by ClerkPhoenix.Plug.AuthPlug.

    ## Usage

    Add the hook to your LiveView modules:

        defmodule MyAppWeb.SomeLive do
          use MyAppWeb, :live_view

          # Require authentication - redirects if not authenticated
          on_mount {ClerkPhoenix.LiveView, :require_auth}

          # Optional authentication - continues without auth
          on_mount {ClerkPhoenix.LiveView, :optional_auth}
        end

    ## Available assigns

    After mounting, these assigns will be available:

    - `@authenticated?` - boolean indicating if user is authenticated
    - `@identity` - map with user identity data (sub, email, name)
    - `@auth_context` - map with authentication context (session_id, authenticated_at)
    - `@clerk_config` - map with frontend configuration for Clerk JavaScript SDK

    ## Configuration

    Configure your OTP app in the hook options:

        on_mount {ClerkPhoenix.LiveView, {:require_auth, otp_app: :my_app}}

    If not specified, the OTP app will be detected from the LiveView module name.
    """

    import Phoenix.LiveView
    import Phoenix.Component

    alias ClerkPhoenix.Config

    require Logger

  @doc """
  On mount callback for LiveView authentication.

  ## Modes

  - `:require_auth` - Requires authentication, redirects to sign-in if not authenticated
  - `:optional_auth` - Provides authentication data if available, continues without auth
  - `{:require_auth, opts}` - Requires auth with custom options
  - `{:optional_auth, opts}` - Optional auth with custom options

  ## Options

  - `:otp_app` - The OTP application name for configuration
  - `:redirect_path` - Custom redirect path for unauthenticated users (default: from config)
  """
  def on_mount(mode, params, session, socket) when mode in [:require_auth, :optional_auth] do
    on_mount({mode, []}, params, session, socket)
  end

  def on_mount({mode, opts}, _params, session, socket) when mode in [:require_auth, :optional_auth] do
    Logger.debug("ClerkPhoenix.LiveView.on_mount - mode: #{mode}")

    otp_app = get_otp_app(socket, opts)

    # Get authentication data from session
    authenticated? = get_session_value(session, "clerk_authenticated", false)
    identity = get_session_value(session, "clerk_identity", nil)
    auth_context = get_session_value(session, "clerk_auth_context", nil)

    # Get clerk config for frontend (from FrontendConfigPlug session data)
    clerk_config = get_session_value(session, "clerk_config", %{})

    Logger.debug("LiveView auth data - authenticated?: #{authenticated?}, identity: #{inspect(identity)}")

    # Assign authentication data to socket
    socket = 
      socket
      |> assign(:authenticated?, authenticated?)
      |> assign(:identity, identity)
      |> assign(:auth_context, auth_context)
      |> assign(:clerk_config, clerk_config)

    case mode do
      :require_auth ->
        if authenticated? do
          {:cont, socket}
        else
          redirect_path = Keyword.get(opts, :redirect_path, Config.sign_in_url(otp_app))
          Logger.debug("LiveView redirecting unauthenticated user to: #{redirect_path}")
          {:halt, redirect(socket, to: redirect_path)}
        end

      :optional_auth ->
        {:cont, socket}
    end
  end

  def on_mount(invalid_mode, _params, _session, _socket) do
    raise ArgumentError, """
    Invalid ClerkPhoenix.LiveView mode: #{inspect(invalid_mode)}

    Valid modes are:
    - :require_auth
    - :optional_auth
    - {:require_auth, opts}
    - {:optional_auth, opts}
    """
  end

  @doc """
  Helper function to check if the current LiveView socket is authenticated.
  """
  def authenticated?(socket) do
    socket.assigns[:authenticated?] == true
  end

  @doc """
  Helper function to get the identity from socket assigns.
  """
  def identity(socket) do
    socket.assigns[:identity]
  end

  @doc """
  Helper function to get the authentication context from socket assigns.
  """
  def auth_context(socket) do
    socket.assigns[:auth_context]
  end

  # Private functions

  defp get_otp_app(socket, opts) do
    cond do
      otp_app = Keyword.get(opts, :otp_app) -> 
        otp_app
      
      socket.view ->
        # Extract OTP app from LiveView module name
        # MyAppWeb.SomeLive -> :my_app
        socket.view
        |> Module.split()
        |> List.first()
        |> Macro.underscore()
        |> String.replace("_web", "")
        |> String.to_atom()
      
      true ->
        raise "Could not determine OTP app for ClerkPhoenix configuration. " <>
              "Please specify :otp_app in on_mount options or ensure LiveView module follows naming conventions."
    end
  end

  defp get_session_value(session, key, default) do
    case Map.get(session, key) do
      nil -> default
      value -> value
    end
  end
end
end