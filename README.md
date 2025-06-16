# ClerkPhoenix

A focused authentication library for Phoenix applications that integrates with Clerk without making assumptions about user management or business logic.

## Design Philosophy

ClerkPhoenix is designed around a core principle: **authentication libraries should handle authentication, not user management**. 

- ✅ **Authentication**: Token validation, identity extraction, session management
- ❌ **User Management**: User models, user business logic, user-specific features

This separation creates cleaner boundaries, better flexibility, and allows applications to define their own user models and management patterns.

## Installation

Add `clerk_phoenix` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:clerk_phoenix, "~> 1.0.0"}
  ]
end
```

## Quick Start

### 1. Configuration

Configure ClerkPhoenix in your `config/runtime.exs`:

```elixir
config :your_app, ClerkPhoenix,
  # Required Clerk credentials
  publishable_key: System.get_env("CLERK_PUBLISHABLE_KEY"),
  secret_key: System.get_env("CLERK_SECRET_KEY"),
  frontend_api_url: System.get_env("CLERK_FRONTEND_API_URL")
```

### 2. Router Setup

```elixir
defmodule YourAppWeb.Router do
  use YourAppWeb, :router
  
  # Authentication pipeline (optional auth)
  pipeline :auth do
    plug ClerkPhoenix.Plug.AuthPlug, otp_app: :your_app
  end
  
  # Require authentication pipeline
  pipeline :require_auth do
    plug ClerkPhoenix.Plug.AuthPlug, mode: :require_auth, otp_app: :your_app
    plug YourApp.UserPlug  # Your app fetches user data
  end
  
  scope "/", YourAppWeb do
    pipe_through [:browser, :auth]
    get "/", PageController, :home
  end
  
  scope "/", YourAppWeb do
    pipe_through [:browser, :require_auth]
    get "/dashboard", PageController, :dashboard
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
    
    render(conn, :dashboard, user: user, identity: identity)
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
  publishable_key: System.get_env("CLERK_PUBLISHABLE_KEY"),
  secret_key: System.get_env("CLERK_SECRET_KEY"),
  frontend_api_url: System.get_env("CLERK_FRONTEND_API_URL"),
  
  # Optional
  api_url: System.get_env("CLERK_API_URL", "https://api.clerk.com"),
  routes: %{
    sign_in: "/sign-in",
    sign_out: "/sign-out",
    after_sign_in: "/dashboard",
    after_sign_out: "/"
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
  
  def mount(_params, _session, socket) do
    identity = ClerkPhoenix.Plug.AuthPlug.identity(socket)
    user = YourApp.Users.get_by_clerk_id(identity["sub"])
    
    {:ok, assign(socket, user: user, identity: identity)}
  end
end
```

## Migration Guide

### Removed Modules

ClerkPhoenix has been refactored to focus purely on authentication. The following modules have been removed:

#### RBAC System
- **Removed**: `ClerkPhoenix.RBAC.Middleware`, `ClerkPhoenix.RBAC.Role`
- **Reason**: Authorization is application-specific business logic
- **Alternative**: Use dedicated authorization libraries like [Bodyguard](https://github.com/schrockwell/bodyguard) or [Canada](https://github.com/jarednorman/canada)

#### Frontend Helpers
- **Removed**: `ClerkPhoenix.Frontend.AuthHelpers`
- **Reason**: Clerk provides official JavaScript SDK
- **Alternative**: Use [@clerk/clerk-js](https://clerk.com/docs/references/javascript/overview) for frontend integration

#### API Authentication Layer
- **Removed**: `ClerkPhoenix.API.*` modules
- **Reason**: Duplicated core authentication functionality
- **Alternative**: Use core ClerkPhoenix authentication with Clerk-generated tokens

#### Security Monitoring
- **Removed**: `ClerkPhoenix.Security.Monitor`
- **Reason**: Application-specific monitoring and alerting
- **Alternative**: Use your application's logging and monitoring tools

### API Changes

#### Before (Old API)
```elixir
user = ClerkPhoenix.Plug.AuthPlug.current_user(conn)
user_id = user["id"]
```

#### After (New API)
```elixir
identity = ClerkPhoenix.Plug.AuthPlug.identity(conn)
clerk_id = identity["sub"]
user = YourApp.Users.get_by_clerk_id(clerk_id)
```

## Security Features

- **JWT Validation**: Cryptographic verification using Clerk's JWKS endpoint
- **Session Management**: Secure session storage with size optimization
- **Token Blacklisting**: Support for revoked token management
- **Session Fingerprinting**: Protection against session hijacking
- **Rate Limiting**: Built-in protection against brute force attacks

## Frontend Integration

For frontend integration, use the official Clerk JavaScript library [@clerk/clerk-js](https://clerk.com/docs/references/javascript/overview) along with ClerkPhoenix for backend authentication.

ClerkPhoenix focuses purely on backend authentication - frontend integration should use Clerk's official JavaScript SDK.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is licensed under the MIT License.