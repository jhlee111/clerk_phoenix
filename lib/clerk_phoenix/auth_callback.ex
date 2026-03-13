defmodule ClerkPhoenix.AuthCallback do
  @moduledoc """
  Macro that injects default controller actions for the Clerk auth callback flow.

  After Clerk.js completes sign-in, it redirects to a callback URL. The `AuthPlug`
  (in the router pipeline) validates the JWT and stores the identity in the Phoenix
  session. The callback action then redirects to the app's main page.

  Similarly, the sign-out action drops the Phoenix session and redirects.

  ## Usage

      defmodule MyAppWeb.AuthCallbackController do
        use MyAppWeb, :controller
        use ClerkPhoenix.AuthCallback, after_sign_in_url: "/dashboard"

        # callback/2 and sign_out/2 are injected and defoverridable
      end

  ## Options

  * `:after_sign_in_url` - Where to redirect after successful sign-in. Default: `"/"`
  * `:after_sign_out_url` - Where to redirect after sign-out. Default: `"/"`

  ## Injected Actions

  * `callback/2` - Redirects to `after_sign_in_url`. AuthPlug has already validated
    the JWT and stored the session by the time this action runs.
  * `sign_out/2` - Drops the Phoenix session and redirects to `after_sign_out_url`.

  Both actions are `defoverridable` — override them for custom behavior (e.g.,
  creating/linking a user record in the callback).
  """

  defmacro __using__(opts) do
    after_sign_in_url = Keyword.get(opts, :after_sign_in_url, "/")
    after_sign_out_url = Keyword.get(opts, :after_sign_out_url, "/")

    quote do
      import Plug.Conn

      def callback(conn, _params) do
        Phoenix.Controller.redirect(conn, to: unquote(after_sign_in_url))
      end

      def sign_out(conn, _params) do
        conn
        |> configure_session(drop: true)
        |> Phoenix.Controller.redirect(to: unquote(after_sign_out_url))
      end

      defoverridable callback: 2, sign_out: 2
    end
  end
end
