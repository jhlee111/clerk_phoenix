if Code.ensure_loaded?(Phoenix.Component) do
  defmodule ClerkPhoenix.Components do
    @moduledoc """
    Phoenix function components for Clerk authentication UI.

    These components render the HTML containers and hooks needed for Clerk.js
    integration with Phoenix LiveView. They replace inline `<script>` tags with
    declarative LiveView components backed by JS hooks.

    ## Prerequisites

    1. Import Clerk JS hooks in your `app.js`:

        import { hooks as clerkHooks } from "clerk_phoenix";
        let liveSocket = new LiveSocket("/live", Socket, {
          hooks: { ...Hooks, ...clerkHooks }
        });

    2. Add the Clerk.js script to your root layout:

        <ClerkPhoenix.Components.clerk_script :if={assigns[:clerk_config]} config={@clerk_config} />

    3. Use `ClerkPhoenix.Plug.FrontendConfigPlug` in your router to provide `@clerk_config`.
    """

    use Phoenix.Component

    @doc """
    Renders the Clerk.js CDN script tag.

    Place this in your root layout (`root.html.heex`). The script loads Clerk.js
    from Clerk's CDN using the `frontend_api_url` from your config.

    In satellite mode (when `config[:manual_init]` is true), the
    `data-clerk-publishable-key` attribute is omitted to prevent Clerk.js
    auto-initialization, and a companion inline script is rendered that globally
    initializes Clerk with `isSatellite: true`. This ensures Clerk is available
    on all pages, not just sign-in/sign-up pages with the `ClerkAuth` hook.

    ## Attributes

    * `config` (required) - Map with `:publishable_key` and `:frontend_api_url` keys.
      Typically `@clerk_config` from `FrontendConfigPlug`.

    ## Example

        <ClerkPhoenix.Components.clerk_script :if={assigns[:clerk_config]} config={@clerk_config} />
    """
    attr :config, :map, required: true

    def clerk_script(assigns) do
      manual_init = assigns.config[:manual_init] || assigns.config["manual_init"] || false
      assigns = assign(assigns, :manual_init, manual_init)

      satellite_init_script =
        if manual_init do
          pk = ClerkPhoenix.JSON.encode!(assigns.config[:publishable_key] || assigns.config["publishable_key"] || "")
          domain = ClerkPhoenix.JSON.encode!(assigns.config[:domain] || "")
          sign_in_url = ClerkPhoenix.JSON.encode!(assigns.config[:primary_sign_in_url] || "")

          "(function(){var pk=#{pk};var domain=#{domain};var signInUrl=#{sign_in_url};function i(){if(!window.Clerk){setTimeout(i,100);return}if(typeof window.Clerk===\"object\")return;if(window.__clerkSatelliteInitPromise)return;var c=new window.Clerk(pk);window.__clerkSatelliteInitPromise=c.load({isSatellite:true,domain:domain||window.location.host,signInUrl:signInUrl}).then(function(){window.Clerk=c}).catch(function(e){console.error(\"Clerk satellite init error:\",e)})}i()})()"
        end

      assigns = assign(assigns, :satellite_init_script, satellite_init_script)

      ~H"""
      <script
        async
        crossorigin="anonymous"
        data-clerk-publishable-key={unless @manual_init, do: @config[:publishable_key] || @config["publishable_key"]}
        src={"#{@config[:frontend_api_url] || @config["frontend_api_url"]}/npm/@clerk/clerk-js@5/dist/clerk.browser.js"}
      >
      </script>
      <script :if={@satellite_init_script}>{raw(@satellite_init_script)}</script>
      """
    end

    @doc """
    Renders a Clerk sign-in widget container.

    This component renders a `<div>` with the `ClerkAuth` hook attached. The hook
    polls for `window.Clerk`, then mounts the Clerk sign-in widget. The div uses
    `phx-update="ignore"` to prevent LiveView from interfering with Clerk's DOM.

    ## Attributes

    * `callback_url` - URL to redirect after successful sign-in. Default: `"/auth/callback"`
    * `sign_up_url` - URL for the "Sign up" link. Default: `"/sign-up"`
    * `class` - Additional CSS classes for the outer wrapper. Default: `""`
    * `id` - DOM id for the widget container. Default: `"clerk-sign-in"`
    * `is_satellite` - Whether this is a satellite domain. Default: `false`
    * `primary_sign_in_url` - Primary domain sign-in URL (required for satellite). Default: `nil`
    * `publishable_key` - Clerk publishable key (required for satellite manual init). Default: `nil`
    * `domain` - Current domain for satellite mode. Default: `nil`

    ## Example

        <ClerkPhoenix.Components.clerk_sign_in
          callback_url="/clerk/callback"
          sign_up_url="/clerk/sign-up"
        />

    ### Satellite domain example

        <ClerkPhoenix.Components.clerk_sign_in
          callback_url="/clerk/callback"
          is_satellite={@clerk_config[:is_satellite]}
          primary_sign_in_url={@clerk_config[:primary_sign_in_url]}
          publishable_key={@clerk_config[:publishable_key]}
          domain={@clerk_config[:domain]}
        />
    """
    attr :callback_url, :string, default: "/auth/callback"
    attr :sign_up_url, :string, default: "/sign-up"
    attr :class, :string, default: ""
    attr :id, :string, default: "clerk-sign-in"
    attr :is_satellite, :boolean, default: false
    attr :primary_sign_in_url, :string, default: nil
    attr :publishable_key, :string, default: nil
    attr :domain, :string, default: nil

    def clerk_sign_in(assigns) do
      ~H"""
      <div
        id={@id}
        phx-hook="ClerkAuth"
        phx-update="ignore"
        data-mode="sign-in"
        data-callback-url={@callback_url}
        data-sign-up-url={@sign_up_url}
        data-is-satellite={to_string(@is_satellite)}
        data-primary-sign-in-url={@primary_sign_in_url}
        data-publishable-key={@publishable_key}
        data-domain={@domain}
        class={@class}
      >
      </div>
      """
    end

    @doc """
    Renders a Clerk sign-up widget container.

    Same as `clerk_sign_in/1` but mounts the sign-up widget.

    ## Attributes

    * `callback_url` - URL to redirect after successful sign-up. Default: `"/auth/callback"`
    * `sign_in_url` - URL for the "Sign in" link. Default: `"/sign-in"`
    * `class` - Additional CSS classes for the outer wrapper. Default: `""`
    * `id` - DOM id for the widget container. Default: `"clerk-sign-up"`
    * `is_satellite` - Whether this is a satellite domain. Default: `false`
    * `primary_sign_in_url` - Primary domain sign-in URL (required for satellite). Default: `nil`
    * `publishable_key` - Clerk publishable key (required for satellite manual init). Default: `nil`
    * `domain` - Current domain for satellite mode. Default: `nil`

    ## Example

        <ClerkPhoenix.Components.clerk_sign_up
          callback_url="/clerk/callback"
          sign_in_url="/clerk/sign-in"
        />
    """
    attr :callback_url, :string, default: "/auth/callback"
    attr :sign_in_url, :string, default: "/sign-in"
    attr :class, :string, default: ""
    attr :id, :string, default: "clerk-sign-up"
    attr :is_satellite, :boolean, default: false
    attr :primary_sign_in_url, :string, default: nil
    attr :publishable_key, :string, default: nil
    attr :domain, :string, default: nil

    def clerk_sign_up(assigns) do
      ~H"""
      <div
        id={@id}
        phx-hook="ClerkAuth"
        phx-update="ignore"
        data-mode="sign-up"
        data-callback-url={@callback_url}
        data-sign-in-url={@sign_in_url}
        data-is-satellite={to_string(@is_satellite)}
        data-primary-sign-in-url={@primary_sign_in_url}
        data-publishable-key={@publishable_key}
        data-domain={@domain}
        class={@class}
      >
      </div>
      """
    end

    @doc """
    Renders a Clerk sign-out trigger.

    Mounts the `ClerkSignOut` hook which calls `Clerk.signOut()` and then
    redirects to the given URL (typically a controller endpoint that drops
    the Phoenix session).

    ## Attributes

    * `redirect_url` - URL to navigate to after Clerk sign-out completes. Default: `"/auth/sign-out"`
    * `id` - DOM id for the container. Default: `"clerk-sign-out"`

    ## Example

        <ClerkPhoenix.Components.clerk_sign_out redirect_url="/clerk/session-destroy" />
    """
    attr :redirect_url, :string, default: "/auth/sign-out"
    attr :id, :string, default: "clerk-sign-out"

    def clerk_sign_out(assigns) do
      ~H"""
      <div id={@id} phx-hook="ClerkSignOut" data-redirect-url={@redirect_url}>
        <p class="text-center text-gray-500">Signing out...</p>
      </div>
      """
    end

    @doc """
    Renders the Clerk session monitor.

    Place this in your app layout. When authenticated, the `ClerkSessionMonitor`
    hook polls `Clerk.session` every 5 seconds and pushes a `clerk:session-expired`
    event if the Clerk session is lost (e.g., revoked in Clerk Dashboard).

    ## Attributes

    * `authenticated` - Whether the user is currently authenticated. Default: `false`
    * `id` - DOM id for the monitor div. Default: `"clerk-session-monitor"`

    ## Example

        <ClerkPhoenix.Components.clerk_session_monitor
          authenticated={@authenticated?}
        />
    """
    attr :authenticated, :boolean, default: false
    attr :id, :string, default: "clerk-session-monitor"

    def clerk_session_monitor(assigns) do
      ~H"""
      <div
        id={@id}
        phx-hook="ClerkSessionMonitor"
        data-authenticated={to_string(@authenticated)}
        style="display:none"
      >
      </div>
      """
    end
  end
end
