defmodule ClerkPhoenix.Plug.SatelliteSyncPlugTest do
  use ExUnit.Case, async: true
  import Plug.Test

  alias ClerkPhoenix.Plug.SatelliteSyncPlug

  @secret_key_base String.duplicate("a", 64)

  defp conn_with_session(method, path) do
    conn(method, path)
    |> Map.put(:secret_key_base, @secret_key_base)
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded]))
    |> Plug.Session.call(Plug.Session.init(
      store: :cookie,
      key: "_test_session",
      signing_salt: "test"
    ))
    |> Plug.Conn.fetch_session()
  end

  describe "call/2" do
    test "passes through when __clerk_synced is not present" do
      conn =
        conn_with_session(:get, "/sign-in")
        |> SatelliteSyncPlug.call(SatelliteSyncPlug.init([]))

      refute conn.halted
    end

    test "redirects and strips __clerk_synced param" do
      conn =
        conn_with_session(:get, "/sign-in?__clerk_synced=true")
        |> SatelliteSyncPlug.call(SatelliteSyncPlug.init([]))

      assert conn.halted
      assert conn.status == 302

      [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location == "/sign-in"
    end

    test "preserves other query params when stripping __clerk_synced" do
      conn =
        conn_with_session(:get, "/callback?ref=home&__clerk_synced=true&lang=en")
        |> SatelliteSyncPlug.call(SatelliteSyncPlug.init([]))

      assert conn.halted

      [location] = Plug.Conn.get_resp_header(conn, "location")
      assert location =~ "/callback?"
      assert location =~ "ref=home"
      assert location =~ "lang=en"
      refute location =~ "__clerk_synced"
    end

    test "sets session flag on sync" do
      conn =
        conn_with_session(:get, "/sign-in?__clerk_synced=true")
        |> SatelliteSyncPlug.call(SatelliteSyncPlug.init([]))

      assert Plug.Conn.get_session(conn, "clerk_satellite_synced") == true
    end

    test "ignores __clerk_synced with non-true values" do
      conn =
        conn_with_session(:get, "/sign-in?__clerk_synced=false")
        |> SatelliteSyncPlug.call(SatelliteSyncPlug.init([]))

      refute conn.halted
    end
  end
end
