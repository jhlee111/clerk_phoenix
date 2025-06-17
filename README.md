# ClerkPhoenix

A focused authentication library for Phoenix applications that integrates with Clerk without making assumptions about user management or business logic.

## Introduction

I am quite new to Elixir and made this library for my own use using [Claude Code](https://claude.ai/code). This library is currently a personal project and is not officially supported or endorsed by Clerk. Use at your own discretion.

## ⚠️ Disclaimer

**This software is provided "as is" without warranty of any kind.** I cannot be held responsible for any damages, data loss, security issues, or other problems that may arise from using this library. Use this software at your own risk and always thoroughly test in your own environment before deploying to production.

## Design Philosophy

ClerkPhoenix is designed around a core principle: **authentication libraries should handle authentication, not user management**. 

- ✅ **Authentication**: Token validation, identity extraction, session management
- ❌ **User Management**: User models, user business logic, user-specific features

This separation creates cleaner boundaries, better flexibility, and allows applications to define their own user models and management patterns.

## Installation

**Note: This package is not published on Hex.** Add `clerk_phoenix` to your list of dependencies in `mix.exs` using the GitHub repository:

```elixir
def deps do
  [
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", tag: "v0.1.2"}
  ]
end
```

Alternatively, you can use a specific branch or commit:

```elixir
def deps do
  [
    # Use latest main branch
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", branch: "main"}
    
    # Or use a specific commit
    # {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", ref: "commit_hash"}
  ]
end
```

## Quick Start

### 1. Configuration

Configure ClerkPhoenix in your `config/runtime.exs`:

```elixir
# For environment variables from .env file (optional)
import Dotenvy

if File.exists?(".env") do
  source!([".env", System.get_env()])
end

config :your_app, ClerkPhoenix,
  # Required Clerk credentials
  publishable_key: env!("CLERK_PUBLISHABLE_KEY"),
  secret_key: env!("CLERK_SECRET_KEY"),
  frontend_api_url: env!("CLERK_FRONTEND_API_URL"),
  # Optional
  api_url: System.get_env("CLERK_API_URL", "https://api.clerk.com"),
  routes: %{
    sign_in: "/sign-in",
    sign_out: "/sign-out",
    after_sign_in: "/member",
    after_sign_out: "/not-signed-in"
  },
  messages: %{
    auth_required: "Please sign in to continue.",
    session_expired: "Your session has expired. Please sign in again."
  }
```

Add Dotenvy to your `mix.exs` dependencies for .env file support:

```elixir
{:dotenvy, "~> 1.0.0"}
```

### 2. Router Setup

```elixir
defmodule YourAppWeb.Router do
  use YourAppWeb, :router
  
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {YourAppWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :assign_clerk_config  # Make Clerk config available globally
  end
  
  # Authentication pipeline (optional auth)
  pipeline :auth do
    plug ClerkPhoenix.Plug.AuthPlug, otp_app: :your_app
  end
  
  # Require authentication pipeline
  pipeline :require_auth do
    plug ClerkPhoenix.Plug.AuthPlug, mode: :require_auth, otp_app: :your_app
    plug YourApp.UserPlug  # Your app fetches user data
  end
  
  # Public routes (no authentication)
  scope "/", YourAppWeb do
    pipe_through :browser
    get "/sign-in", PageController, :sign_in
    get "/sign-up", PageController, :sign_up
  end
  
  scope "/", YourAppWeb do
    pipe_through [:browser, :auth]
    get "/", PageController, :home
  end
  
  scope "/", YourAppWeb do
    pipe_through [:browser, :require_auth]
    get "/member", PageController, :member
  end
  
  # Private function to make Clerk config available in all templates
  defp assign_clerk_config(conn, _opts) do
    clerk_config = Application.get_env(:your_app, ClerkPhoenix, [])
    assign(conn, :clerk_config, clerk_config)
  end
end
```

### 3. User Management (Your Responsibility)

```elixir
defmodule YourApp.UserPlug do
  def init(opts), do: opts
  
  def call(conn, _opts) do
    case ClerkPhoenix.Plug.AuthPlug.identity(conn) do
      %{"sub" => clerk_id} ->
        user = YourApp.Users.get_by_clerk_id(clerk_id)
        Plug.Conn.assign(conn, :current_user, user)
      nil ->
        Plug.Conn.assign(conn, :current_user, nil)
    end
  end
end
```

### 4. Controller Usage

```elixir
defmodule YourAppWeb.DashboardController do
  use YourAppWeb, :controller
  
  def index(conn, _params) do
    identity = ClerkPhoenix.Plug.AuthPlug.identity(conn)
    user = conn.assigns.current_user
    
    render(conn, :member, user: user, identity: identity)
  end
end
```

## What ClerkPhoenix Provides

### Connection Assigns

ClerkPhoenix sets these connection assigns:

```elixir
conn.assigns.authenticated?  # boolean - authentication status
conn.assigns.identity       # map - extracted identity claims
conn.assigns.auth_context   # map - authentication metadata
conn.assigns.token_claims   # map - raw JWT claims (optional/debug)
```

### Helper Functions

```elixir
# Check authentication status
ClerkPhoenix.Plug.AuthPlug.authenticated?(conn)

# Get identity claims
ClerkPhoenix.Plug.AuthPlug.identity(conn)
# => %{"sub" => "user_123", "email" => "user@example.com", "name" => "John Doe"}

# Get authentication context
ClerkPhoenix.Plug.AuthPlug.auth_context(conn)
# => %{authenticated_at: 1640995200, session_id: "sess_123", ...}

# Get raw JWT claims (debugging)
ClerkPhoenix.Plug.AuthPlug.token_claims(conn)
```

## Configuration Options

### Basic Configuration

```elixir
config :your_app, ClerkPhoenix,
  # Required
  publishable_key: env!("CLERK_PUBLISHABLE_KEY"),
  secret_key: env!("CLERK_SECRET_KEY"),
  frontend_api_url: env!("CLERK_FRONTEND_API_URL"),
  
  # Optional
  api_url: System.get_env("CLERK_API_URL", "https://api.clerk.com"),
  routes: %{
    sign_in: "/sign-in",
    sign_out: "/sign-out",
    after_sign_in: "/member",
    after_sign_out: "/not-signed-in"
  },
  messages: %{
    auth_required: "Please sign in to continue.",
    session_expired: "Your session has expired. Please sign in again."
  }
```

### Identity Mapping Configuration

Customize how identity claims are extracted from JWT tokens:

```elixir
config :your_app, ClerkPhoenix,
  # ... other config ...
  
  identity_mapping: %{
    subject_field: ["sub", "id", "user_id"],
    email_field: ["email", "primary_email_address"],
    name_field: ["name", "full_name"],
    first_name_field: ["given_name", "first_name"],
    last_name_field: ["family_name", "last_name"],
    image_field: ["picture", "image_url", "avatar"],
    organizations_field: ["org", "organizations"]
  }
```

## Authentication Modes

### Optional Authentication

```elixir
# Tries to authenticate but continues without user if no token
plug ClerkPhoenix.Plug.AuthPlug, otp_app: :your_app
```

### Required Authentication

```elixir
# Requires authentication, redirects to sign-in on failure
plug ClerkPhoenix.Plug.AuthPlug, mode: :require_auth, otp_app: :your_app
```

**Note**: Use `mode: :require_auth` in the options, not as a separate parameter.

### Custom Failure Handling

```elixir
# JSON API responses
plug ClerkPhoenix.Plug.AuthPlug, 
  mode: :require_auth, 
  on_auth_failure: :json,
  otp_app: :your_app

# Custom redirect
plug ClerkPhoenix.Plug.AuthPlug, 
  mode: :require_auth,
  redirect_path: "/custom-login",
  otp_app: :your_app
```

## Application Integration Patterns

### User Management Example

```elixir
defmodule YourApp.Users do
  def get_by_clerk_id(clerk_id) do
    Repo.get_by(User, clerk_id: clerk_id)
  end
end
```

### LiveView Integration

```elixir
defmodule YourAppWeb.DashboardLive do
  use YourAppWeb, :live_view
  
  def mount(_params, session, socket) do
    # Access authentication data from session assigns
    authenticated? = Map.get(session, "authenticated?", false)
    identity = Map.get(session, "identity")
    
    # Fetch user data if authenticated
    user = if authenticated? && identity do
      YourApp.Users.get_by_clerk_id(identity["sub"])
    else
      nil
    end
    
    {:ok, assign(socket, user: user, identity: identity, authenticated?: authenticated?)}
  end
end
```


## Security Features

- **JWT Validation**: Cryptographic verification using Clerk's JWKS endpoint
- **Session Management**: Secure session storage with size optimization
- **Token Blacklisting**: Support for revoked token management
- **Session Fingerprinting**: Protection against session hijacking
- **Rate Limiting**: Built-in protection against brute force attacks

## Frontend Integration

ClerkPhoenix focuses on backend authentication while frontend integration uses Clerk's official JavaScript SDK.

### ClerkJS CDN Integration

Add the Clerk JavaScript SDK to your root layout template:

```heex
<!-- In your root.html.heex -->
<script
  async
  crossorigin="anonymous"
  data-clerk-publishable-key={@clerk_config[:publishable_key]}
  src={"#{@clerk_config[:frontend_api_url]}/npm/@clerk/clerk-js@5/dist/clerk.browser.js"}
  type="text/javascript"
>
</script>
<script>
  window.__clerk_config__ = <%= ClerkPhoenix.Config.get_clerk_javascript_config(:your_app) |> Phoenix.HTML.raw %>
</script>
```

### JavaScript Initialization

Initialize Clerk in your `app.js`:

```javascript
window.addEventListener('load', async () => {
  if (!window.Clerk) {
    console.error('Clerk is not loaded')
    return
  }

  try {
    await window.Clerk.load(window.__clerk_config__)
    console.log('Clerk loaded successfully')

    // Mount Clerk UI components
    const userButtonElement = document.getElementById('clerk-user-button')
    const signInElement = document.getElementById('clerk-sign-in')
    const signUpElement = document.getElementById('clerk-sign-up')

    if (userButtonElement) {
      window.Clerk.mountUserButton(userButtonElement)
    }

    if (signInElement) {
      window.Clerk.mountSignIn(signInElement)
    }
    
    if (signUpElement) {
      window.Clerk.mountSignUp(signUpElement)
    }
  } catch (error) {
    console.error('Error loading Clerk:', error)
  }
})
```

### Template Integration

Access Clerk configuration and authentication state in templates:

```heex
<!-- Access nested config values -->
<%= @clerk_config[:routes][:sign_in] %>

<!-- Conditional rendering based on authentication -->
<%= if @authenticated? do %>
  <div id="clerk-user-button"></div>
<% else %>
  <a href={@clerk_config[:routes][:sign_in]}>Sign In</a>
<% end %>

<!-- Mount Clerk components -->
<div id="clerk-sign-in"></div>
<div id="clerk-sign-up"></div>
```

### Safe Config Access

Use `get_in/3` for safe nested access with fallbacks:

```heex
<%= get_in(@clerk_config, [:routes, :sign_in]) || "/sign-in" %>
<%= get_in(@clerk_config, [:messages, :auth_required]) || "Please sign in" %>
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is licensed under the MIT License.