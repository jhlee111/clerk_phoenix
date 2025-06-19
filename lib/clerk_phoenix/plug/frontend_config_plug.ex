defmodule ClerkPhoenix.Plug.FrontendConfigPlug do
  @moduledoc """
  A plug that assigns Clerk frontend configuration to the connection.
  
  This plug provides frontend-safe configuration needed for Clerk's JavaScript SDK,
  including publishable key, frontend API URL, and sign-in/sign-up routes.
  
  ## Usage
  
  Add to your router pipeline:
  
      pipeline :browser do
        plug :accepts, ["html"]
        plug :fetch_session
        plug :fetch_live_flash
        plug :put_root_layout, html: {MyAppWeb.Layouts, :root}
        plug :protect_from_forgery
        plug :put_secure_browser_headers
        plug ClerkPhoenix.Plug.FrontendConfigPlug, otp_app: :my_app
      end
  
  ## Configuration
  
      config :my_app, ClerkPhoenix,
        publishable_key: "pk_test_...",
        frontend_api_url: "https://...",
        sign_in_url: "/sign-in",
        sign_up_url: "/sign-up",
        after_sign_in_url: "/dashboard",
        after_sign_up_url: "/profile"
  
  ## Assigns
  
  This plug assigns `@clerk_config` to the connection with the following keys:
  - `:publishable_key` - Clerk publishable key for JavaScript SDK
  - `:frontend_api_url` - Clerk frontend API URL for CDN script
  - `:sign_in_url` - URL for sign-in page (default: "/sign-in")
  - `:sign_up_url` - URL for sign-up page (default: "/sign-up")
  - `:after_sign_in_url` - Redirect URL after successful sign-in (default: "/")
  - `:after_sign_up_url` - Redirect URL after successful sign-up (default: "/")
  """
  
  import Plug.Conn
  
  @default_config %{
    sign_in_url: "/sign-in",
    sign_up_url: "/sign-up", 
    after_sign_in_url: "/",
    after_sign_up_url: "/"
  }
  
  def init(opts) do
    otp_app = Keyword.fetch!(opts, :otp_app)
    %{otp_app: otp_app}
  end
  
  def call(conn, %{otp_app: otp_app}) do
    # Skip in test environment for performance
    if Mix.env() == :test do
      conn
    else
      assign_clerk_config(conn, otp_app)
    end
  end
  
  defp assign_clerk_config(conn, otp_app) do
    config = Application.get_env(otp_app, ClerkPhoenix, [])
    
    # Only assign if we have required configuration
    case {config[:publishable_key], config[:frontend_api_url]} do
      {nil, _} -> 
        conn
      {_, nil} -> 
        conn
      {publishable_key, frontend_api_url} ->
        frontend_config = build_frontend_config(config, publishable_key, frontend_api_url)
        assign(conn, :clerk_config, frontend_config)
    end
  end
  
  defp build_frontend_config(config, publishable_key, frontend_api_url) do
    @default_config
    |> Map.put(:publishable_key, publishable_key)
    |> Map.put(:frontend_api_url, frontend_api_url)
    |> Map.put(:sign_in_url, config[:sign_in_url] || @default_config.sign_in_url)
    |> Map.put(:sign_up_url, config[:sign_up_url] || @default_config.sign_up_url)
    |> Map.put(:after_sign_in_url, config[:after_sign_in_url] || @default_config.after_sign_in_url)
    |> Map.put(:after_sign_up_url, config[:after_sign_up_url] || @default_config.after_sign_up_url)
  end
end