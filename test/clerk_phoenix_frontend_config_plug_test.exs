defmodule ClerkPhoenix.Plug.FrontendConfigPlugTest do
  use ExUnit.Case, async: true
  import Plug.Test

  alias ClerkPhoenix.Plug.FrontendConfigPlug

  defp conn_with_session(method, path) do
    conn(method, path)
    |> Plug.Session.call(Plug.Session.init(
      store: :cookie,
      key: "_test_session",
      signing_salt: "test"
    ))
    |> Plug.Conn.fetch_session()
  end

  describe "satellite config" do
    test "default config does not include satellite fields as true" do
      conn =
        conn_with_session(:get, "/")
        |> FrontendConfigPlug.call(FrontendConfigPlug.init(otp_app: :my_app))

      config = conn.assigns.clerk_config

      assert config.is_satellite == false
      assert config.manual_init == false
      assert config.publishable_key == "pk_test"
    end

    test "satellite=true adds satellite fields to clerk_config" do
      Application.put_env(:satellite_plug_app, ClerkPhoenix,
        publishable_key: "pk_test",
        secret_key: "sk_test",
        frontend_api_url: "https://test.clerk.dev",
        is_satellite: true,
        primary_sign_in_url: "https://primary.example.com/sign-in"
      )

      conn =
        conn_with_session(:get, "/")
        |> Map.put(:host, "satellite.example.com")
        |> FrontendConfigPlug.call(FrontendConfigPlug.init(otp_app: :satellite_plug_app))

      config = conn.assigns.clerk_config

      assert config.is_satellite == true
      assert config.manual_init == true
      assert config.primary_sign_in_url == "https://primary.example.com/sign-in"
      assert config.domain == "satellite.example.com"
    after
      Application.delete_env(:satellite_plug_app, ClerkPhoenix)
    end

    test "dynamic satellite detection with function" do
      Application.put_env(:satellite_dynamic_app, ClerkPhoenix,
        publishable_key: "pk_test",
        secret_key: "sk_test",
        frontend_api_url: "https://test.clerk.dev",
        is_satellite: fn conn -> conn.host == "satellite.example.com" end,
        primary_sign_in_url: "https://primary.example.com/sign-in"
      )

      # Satellite domain
      satellite_conn =
        conn_with_session(:get, "/")
        |> Map.put(:host, "satellite.example.com")
        |> FrontendConfigPlug.call(FrontendConfigPlug.init(otp_app: :satellite_dynamic_app))

      assert satellite_conn.assigns.clerk_config.is_satellite == true
      assert satellite_conn.assigns.clerk_config.manual_init == true

      # Primary domain
      primary_conn =
        conn_with_session(:get, "/")
        |> Map.put(:host, "primary.example.com")
        |> FrontendConfigPlug.call(FrontendConfigPlug.init(otp_app: :satellite_dynamic_app))

      assert primary_conn.assigns.clerk_config.is_satellite == false
      assert primary_conn.assigns.clerk_config.manual_init == false
    after
      Application.delete_env(:satellite_dynamic_app, ClerkPhoenix)
    end

    test "stores satellite config in session for LiveView" do
      Application.put_env(:satellite_session_app, ClerkPhoenix,
        publishable_key: "pk_test",
        secret_key: "sk_test",
        frontend_api_url: "https://test.clerk.dev",
        is_satellite: true,
        primary_sign_in_url: "https://primary.example.com/sign-in"
      )

      conn =
        conn_with_session(:get, "/")
        |> FrontendConfigPlug.call(FrontendConfigPlug.init(otp_app: :satellite_session_app))

      session_config = Plug.Conn.get_session(conn, "clerk_config")
      assert session_config.is_satellite == true
      assert session_config.manual_init == true
    after
      Application.delete_env(:satellite_session_app, ClerkPhoenix)
    end
  end
end
