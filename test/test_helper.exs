ExUnit.start()

# Configure test environment
Application.put_env(:my_app, ClerkPhoenix,
  publishable_key: "pk_test",
  secret_key: "sk_test",
  frontend_api_url: "https://test.clerk.dev"
)

Application.put_env(:clerk_phoenix, ClerkPhoenix,
  publishable_key: "pk_test",
  secret_key: "sk_test",
  frontend_api_url: "https://test.clerk.dev"
)
