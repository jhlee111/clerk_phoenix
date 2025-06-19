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

## Prerequisites

- Phoenix 1.7+ application
- Clerk account and application configured ([Get started here](https://dashboard.clerk.com))
- Basic understanding of Phoenix plugs and pipelines

## Installation

**Note: This package is not published on Hex.** Add `clerk_phoenix` to your list of dependencies in `mix.exs` using the GitHub repository:

### Recommended: Use Stable Release Tag

```elixir
def deps do
  [
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", tag: "v0.1.3"}
  ]
end
```

### Available Release Tags

| Version | Release Date | Commit | Description |
|---------|-------------|---------|-------------|
| `v0.1.3` | Today | `TBD` | Latest stable - Added FrontendConfigPlug for complete frontend integration |
| `v0.1.2` | 2 days ago | `b4408b8` | Comprehensive cleanup and modernization |
| `v0.1.1` | 3 days ago | `7d84e71` | Fixed optional auth redirect loop |
| `v0.1.0` | 3 days ago | `c7b8a5e` | Initial release |

### Alternative Installation Methods

```elixir
def deps do
  [
    # Use a specific version tag (recommended for production)
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", tag: "v0.1.3"},
    
    # Use latest main branch (for development)
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", branch: "main"},
    
    # Use a specific commit
    {:clerk_phoenix, git: "https://github.com/jhlee111/clerk_phoenix.git", ref: "b4408b8"}
  ]
end
```

**💡 Tip:** Use tagged versions for production applications to ensure stability.

## Quick Start

### 1. Get Your Clerk Keys

1. Go to your [Clerk Dashboard](https://dashboard.clerk.com)
2. Select your application
3. Go to "API Keys" section
4. Copy your keys

### 2. Environment Variables

Create a `.env` file in your project root:

```bash
CLERK_PUBLISHABLE_KEY=pk_test_your_publishable_key_here
CLERK_SECRET_KEY=sk_test_your_secret_key_here
CLERK_FRONTEND_API_URL=https://your-clerk-frontend-api.clerk.accounts.dev
```

**Important:** Add `.env` to your `.gitignore` file to keep secrets secure.

### 3. Configuration

Configure ClerkPhoenix in your `config/runtime.exs`:

```elixir
import Config
import Dotenvy
require Logger

# Load .env file if it exists
if File.exists?(".env") do
  Logger.info("found .env file")
  source!([".env", System.get_env()])
else
  Logger.warning("cannot find .env file to load")
end

# Configure ClerkPhoenix
config :your_app, ClerkPhoenix,
  publishable_key: env!("CLERK_PUBLISHABLE_KEY"),
  secret_key: env!("CLERK_SECRET_KEY"),
  frontend_api_url: env!("CLERK_FRONTEND_API_URL"),
  # Optional frontend route configurations
  sign_in_url: "/sign-in",
  sign_up_url: "/sign-up",
  after_sign_in_url: "/dashboard",
  after_sign_up_url: "/profile"
```

**Additional dependencies:** You'll also need `{:dotenvy, "~> 1.0.0"}` for .env file support. Run `mix deps.get` to install dependencies.

### 4. Router Setup

Update your `lib/your_app_web/router.ex`:

```elixir
defmodule YourAppWeb.Router do
  use YourAppWeb, :router

  # Base browser pipeline
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {YourAppWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug ClerkPhoenix.Plug.FrontendConfigPlug, otp_app: :your_app # Make Clerk config available in templates
  end

  # Optional authentication pipeline
  pipeline :auth do
    plug ClerkPhoenix.Plug.AuthPlug, otp_app: :your_app
  end

  # Required authentication pipeline
  pipeline :require_auth do
    plug ClerkPhoenix.Plug.AuthPlug, mode: :require_auth, otp_app: :your_app
    # Add your user fetching plug here
    # plug YourApp.UserPlug
  end

  # Public routes
  scope "/", YourAppWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/sign-in", PageController, :sign_in
    get "/sign-up", PageController, :sign_up
  end

  # Optional auth routes (user might or might not be signed in)
  scope "/", YourAppWeb do
    pipe_through [:browser, :auth]

    get "/dashboard", PageController, :dashboard
  end

  # Protected routes (authentication required)
  scope "/", YourAppWeb do
    pipe_through [:browser, :require_auth]

    get "/profile", PageController, :profile
    get "/settings", PageController, :settings
  end

end
```

## Available Connection Assigns

ClerkPhoenix automatically sets these assigns on the connection:

```elixir
# In your controllers and templates
@authenticated?  # boolean - whether user is authenticated
@identity       # map - extracted identity claims from JWT
@auth_context   # map - authentication metadata
@token_claims   # map - raw JWT claims (for debugging)
@clerk_config   # map - frontend configuration for Clerk JavaScript SDK
```

## User Management Integration

ClerkPhoenix handles authentication only. For user management, create a plug to fetch your user data:

```elixir
defmodule YourApp.UserPlug do
  @behaviour Plug
  
  def init(opts), do: opts
  
  def call(conn, _opts) do
    case conn.assigns.identity do
      %{"sub" => clerk_id} ->
        user = YourApp.Users.get_by_clerk_id(clerk_id)
        Plug.Conn.assign(conn, :current_user, user)
      nil ->
        Plug.Conn.assign(conn, :current_user, nil)
    end
  end
end
```

Add this plug to your `:require_auth` pipeline:

```elixir
pipeline :require_auth do
  plug ClerkPhoenix.Plug.AuthPlug, mode: :require_auth, otp_app: :your_app
  plug YourApp.UserPlug
end
```

## Using Clerk UI Components

Clerk provides pre-built, customizable UI components that handle authentication flows. These components give you a complete authentication system without building forms from scratch.

### Available Components

- **SignIn**: Complete sign-in form with email, social login, phone verification
- **SignUp**: Registration form with email verification and validation  
- **UserButton**: User profile dropdown with account management
- **UserProfile**: Full profile management interface

### Layout Template Setup

Update your `lib/your_app_web/components/layouts/root.html.heex`:

```heex
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="csrf-token" content={get_csrf_token()} />
    <.live_title default="YourApp">
      {assigns[:page_title]}
    </.live_title>
    <link phx-track-static rel="stylesheet" href={~p"/assets/css/app.css"} />
    <script defer phx-track-static type="text/javascript" src={~p"/assets/js/app.js"}>
    </script>
    
    <!-- Clerk JavaScript SDK -->
    <script
      async
      crossorigin="anonymous"
      data-clerk-publishable-key={@clerk_config[:publishable_key]}
      src={"#{@clerk_config[:frontend_api_url]}/npm/@clerk/clerk-js@5/dist/clerk.browser.js"}
      type="text/javascript"
    >
    </script>
    
    <!-- Clerk Configuration -->
    <script>
      window.__clerk_config__ = <%= raw(Jason.encode!(@clerk_config || %{})) %>
    </script>
  </head>
  <body>
    {@inner_content}
  </body>
</html>
```

### JavaScript Setup

Add to your `assets/js/app.js`:

```javascript
// Initialize Clerk when available
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

### Authentication Templates

#### Sign In Template (`lib/your_app_web/controllers/page_html/sign_in.html.heex`)

```heex
<div class="min-h-screen flex items-center justify-center">
  <div class="max-w-md w-full space-y-8">
    <div>
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Sign in to your account
      </h2>
    </div>
    <div id="clerk-sign-in"></div>
  </div>
</div>
```

#### Sign Up Template (`lib/your_app_web/controllers/page_html/sign_up.html.heex`)

```heex
<div class="min-h-screen flex items-center justify-center">
  <div class="max-w-md w-full space-y-8">
    <div>
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Create your account
      </h2>
    </div>
    <div id="clerk-sign-up"></div>
  </div>
</div>
```

#### Protected Page Template

```heex
<div class="container mx-auto px-4 py-8">
  <div class="flex justify-between items-center mb-8">
    <h1 class="text-3xl font-bold">Welcome to Your Dashboard</h1>
    <div id="clerk-user-button"></div>
  </div>
  
  <!-- Display authentication status -->
  <div class="mb-4">
    <p>Authentication Status: <strong>{if @authenticated?, do: "Signed In", else: "Not Signed In"}</strong></p>
    
    <!-- Display user identity if available -->
    <div :if={@identity}>
      <h3 class="text-lg font-semibold mt-4">User Identity:</h3>
      <pre class="bg-gray-100 p-4 rounded mt-2"><%= JSON.encode!(@identity, pretty: true) %></pre>
    </div>
  </div>
  
  <!-- Your protected content here -->
</div>
```

#### User Button in Navigation

```heex
<!-- Show content based on authentication status -->
<div :if={@authenticated?}>
  <p>Welcome back!</p>
  <div id="clerk-user-button"></div>
</div>

<div :if={!@authenticated?}>
  <a href="/sign-in" class="btn btn-primary">Sign In</a>
</div>
```

### Template Integration Tips

Access Clerk configuration safely in templates:

```heex
<!-- Safe nested config access -->
<%= get_in(@clerk_config, [:routes, :sign_in]) || "/sign-in" %>
<%= get_in(@clerk_config, [:messages, :auth_required]) || "Please sign in" %>

<!-- Conditional rendering -->
<%= if @authenticated? do %>
  <div id="clerk-user-button"></div>
<% else %>
  <a href={@clerk_config[:routes][:sign_in]}>Sign In</a>
<% end %>
```

## Helper Functions

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

## Advanced Configuration

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

## Testing

### Test Configuration (`config/test.exs`)

```elixir
config :your_app, ClerkPhoenix,
  publishable_key: "pk_test_test_key",
  secret_key: "sk_test_test_key",
  frontend_api_url: "https://test-frontend-api.clerk.accounts.dev"
```

### Testing with Authenticated Users

```elixir
defmodule YourAppWeb.PageControllerTest do
  use YourAppWeb.ConnCase
  
  test "protected page requires authentication", %{conn: conn} do
    conn = get(conn, ~p"/profile")
    assert redirected_to(conn) == ~p"/sign-in"
  end
  
  test "protected page works with authentication", %{conn: conn} do
    # Mock authenticated user
    conn = 
      conn
      |> assign(:authenticated?, true)
      |> assign(:identity, %{"sub" => "user_123", "email" => "test@example.com"})
    
    conn = get(conn, ~p"/profile")
    assert html_response(conn, 200) =~ "Welcome to Your Dashboard"
  end
end
```

## Troubleshooting

### Common Issues

1. **"Clerk config not found"**: Ensure you've added `ClerkPhoenix.Plug.FrontendConfigPlug` to your browser pipeline
2. **"Invalid token"**: Check that your secret key and publishable key match your Clerk application
3. **"Frontend API URL not found"**: Verify your frontend API URL is correctly set in environment variables
4. **JavaScript errors**: Make sure the Clerk script is loaded before trying to mount components

### Debugging

Enable debug logging in development:

```elixir
config :logger, level: :debug
```

View authentication assigns in your templates:

```heex
<div style="display: none;">
  <pre>Auth Status: <%= inspect(@authenticated?) %></pre>
  <pre>Identity: <%= inspect(@identity) %></pre>
  <pre>Auth Context: <%= inspect(@auth_context) %></pre>
</div>
```

## Security Considerations

1. **Never commit secrets**: Keep `.env` files out of version control
2. **Use environment variables**: All sensitive configuration should come from environment variables
3. **HTTPS in production**: Always use HTTPS in production environments
4. **Validate tokens**: ClerkPhoenix automatically validates JWT tokens using Clerk's JWKS endpoint
5. **Session security**: Configure secure session settings in your Phoenix endpoint

## Resources

- [Clerk Dashboard](https://dashboard.clerk.com)
- [Phoenix Framework Documentation](https://hexdocs.pm/phoenix)
- [Clerk JavaScript SDK](https://clerk.com/docs/reference/javascript/overview)

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is licensed under the MIT License.