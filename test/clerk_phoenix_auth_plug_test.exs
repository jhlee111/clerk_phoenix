defmodule ClerkPhoenix.Plug.AuthPlugTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn
  import Phoenix.ConnTest

  alias ClerkPhoenix.Plug.AuthPlug

  # Helper to create a test connection with session support
  defp conn_with_session(method, path) do
    conn(method, path)
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded, :multipart]))
    |> Plug.Session.call(Plug.Session.init(
      store: :cookie,
      key: "_test_session",
      signing_salt: "test"
    ))
    |> fetch_session()
    |> fetch_flash()
  end

  describe "public interface - what applications actually use" do
    test "sets authentication assigns when no token present" do
      conn = conn_with_session(:get, "/")
             |> AuthPlug.call(AuthPlug.init(otp_app: :my_app))

      # These are the assigns applications rely on
      assert conn.assigns.authenticated? == false
      assert conn.assigns.identity == nil
      assert conn.assigns.auth_context == nil
      assert conn.assigns.token_claims == nil
    end

    test "helper functions work correctly" do
      conn = conn(:get, "/")
             |> Plug.Conn.assign(:authenticated?, true)
             |> Plug.Conn.assign(:identity, %{"sub" => "user_123", "email" => "test@example.com"})

      # These are the helper functions applications use
      assert AuthPlug.authenticated?(conn) == true
      assert AuthPlug.identity(conn) == %{"sub" => "user_123", "email" => "test@example.com"}

      # Test with unauthenticated conn
      unauth_conn = conn(:get, "/")
                    |> Plug.Conn.assign(:authenticated?, false)
                    |> Plug.Conn.assign(:identity, nil)

      assert AuthPlug.authenticated?(unauth_conn) == false
      assert AuthPlug.identity(unauth_conn) == nil
    end

    test "require_auth mode redirects when not authenticated" do
      opts = AuthPlug.init(mode: :require_auth, otp_app: :my_app)
      conn = conn_with_session(:get, "/dashboard")
             |> AuthPlug.call(opts)

      # Should redirect to sign-in
      assert conn.halted == true
      assert conn.status == 302
    end

    test "optional auth mode continues when not authenticated" do
      conn = conn_with_session(:get, "/")
             |> AuthPlug.call(AuthPlug.init(otp_app: :my_app))

      # Should not redirect, just set nil assigns
      assert conn.halted == false
      assert conn.assigns.authenticated? == false
    end

    test "initialization modes work correctly" do
      # Test require_auth mode
      require_opts = AuthPlug.init(:require_auth)
      assert require_opts[:mode] == :require_auth
      assert require_opts[:on_auth_failure] == :redirect

      # Test optional mode (default)
      optional_opts = AuthPlug.init(otp_app: :my_app)
      assert optional_opts[:mode] == :optional
      assert optional_opts[:on_auth_failure] == :redirect
    end

    test "JSON failure mode returns JSON response" do
      conn = conn_with_session(:get, "/api/data")
             |> put_req_header("accept", "application/json")
             |> AuthPlug.call(AuthPlug.init(mode: :require_auth, on_auth_failure: :json, otp_app: :my_app))

      assert conn.halted == true
      assert conn.status == 401
      assert get_resp_header(conn, "content-type") |> List.first() =~ "application/json"
    end
  end

  describe "configuration" do
    test "validates required otp_app configuration" do
      assert_raise RuntimeError, ~r/Could not determine OTP app/, fn ->
        conn(:get, "/")
        |> AuthPlug.call(AuthPlug.init([]))
      end
    end

    test "accepts otp_app in options" do
      conn = conn_with_session(:get, "/")
             |> AuthPlug.call(AuthPlug.init(otp_app: :my_app))

      # Should not raise, and should set assigns
      assert conn.assigns.authenticated? == false
    end
  end
end