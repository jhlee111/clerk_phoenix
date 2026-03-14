defmodule ClerkPhoenix.Plug.SatelliteSyncPlug do
  @moduledoc """
  Handles the `__clerk_synced` query parameter in Clerk satellite domain flows.

  When Clerk authenticates a user on a satellite domain, the primary domain redirects
  back with `?__clerk_synced=true`. This plug detects that parameter, strips it from
  the URL, and redirects to the clean URL so the parameter doesn't persist in
  bookmarks or logs.

  ## Usage

  Add this plug to your router pipeline **before** the auth plug:

      pipeline :browser do
        plug :accepts, ["html"]
        plug :fetch_session
        plug ClerkPhoenix.Plug.SatelliteSyncPlug
        plug ClerkPhoenix.Plug.FrontendConfigPlug, otp_app: :my_app
        plug ClerkPhoenix.Plug.AuthPlug, otp_app: :my_app
      end

  This plug is a no-op when `__clerk_synced` is not present in the query string.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.params["__clerk_synced"] do
      "true" ->
        clean_url = build_clean_url(conn)

        conn
        |> put_session("clerk_satellite_synced", true)
        |> Phoenix.Controller.redirect(to: clean_url)
        |> halt()

      _ ->
        conn
    end
  end

  defp build_clean_url(conn) do
    query_params =
      conn.query_string
      |> URI.decode_query()
      |> Map.delete("__clerk_synced")

    case URI.encode_query(query_params) do
      "" -> conn.request_path
      qs -> "#{conn.request_path}?#{qs}"
    end
  end
end
