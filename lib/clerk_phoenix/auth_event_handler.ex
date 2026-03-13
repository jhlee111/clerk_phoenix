if Code.ensure_loaded?(Phoenix.LiveView) do
  defmodule ClerkPhoenix.AuthEventHandler do
    @moduledoc """
    Macro that injects default `handle_event/3` clauses for Clerk JS hook events.

    When a LiveView uses Clerk components (`clerk_sign_in`, `clerk_sign_up`, etc.),
    the JS hooks push events that need to be handled server-side. This macro provides
    sensible defaults that can be overridden.

    ## Usage

        defmodule MyAppWeb.SignInLive do
          use MyAppWeb, :live_view
          use ClerkPhoenix.AuthEventHandler, callback_url: "/clerk/callback"

          def render(assigns) do
            ~H\"\"\"
            <ClerkPhoenix.Components.clerk_sign_in callback_url="/clerk/callback" />
            \"\"\"
          end
        end

    ## Options

    * `:callback_url` - Where to redirect when user is already signed in.
      Default: `"/auth/callback"`
    * `:sign_out_url` - Where to redirect on session expiry.
      Default: `"/auth/sign-out"`

    ## Injected Event Handlers

    * `"clerk:signed-in"` — User was already signed in when the widget loaded.
      Redirects to `callback_url`.
    * `"clerk:error"` — Clerk.js encountered an error loading or mounting.
      Sets a flash error message.
    * `"clerk:session-expired"` — `ClerkSessionMonitor` detected that the Clerk
      session was revoked or expired. Flashes a message and redirects to `sign_out_url`.

    All handlers are `defoverridable`, so you can customize any of them in your LiveView.
    """

    defmacro __using__(opts) do
      callback_url = Keyword.get(opts, :callback_url, "/auth/callback")
      sign_out_url = Keyword.get(opts, :sign_out_url, "/auth/sign-out")

      quote do
        def handle_event("clerk:signed-in", _params, socket) do
          {:noreply, Phoenix.LiveView.redirect(socket, to: unquote(callback_url))}
        end

        def handle_event("clerk:error", %{"error" => message}, socket) do
          {:noreply, Phoenix.LiveView.put_flash(socket, :error, "Authentication error: #{message}")}
        end

        def handle_event("clerk:session-expired", _params, socket) do
          {:noreply,
           socket
           |> Phoenix.LiveView.put_flash(:info, "Your session has expired. Please sign in again.")
           |> Phoenix.LiveView.redirect(to: unquote(sign_out_url))}
        end

        defoverridable handle_event: 3
      end
    end
  end
end
