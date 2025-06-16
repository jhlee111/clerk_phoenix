defmodule ClerkPhoenix.ConfigTest do
  use ExUnit.Case, async: true

  alias ClerkPhoenix.Config

  describe "public configuration interface" do
    test "gets configuration with defaults" do
      config = Config.get_config(:my_app)

      # Applications rely on these being available
      assert config.publishable_key == "pk_test"
      assert config.secret_key == "sk_test"
      assert config.frontend_api_url == "https://test.clerk.dev"

      # Should include defaults
      assert config.api_url == "https://api.clerk.com"
      assert config.routes.sign_in == "/sign-in"
      assert config.messages.auth_required == "Please sign in to continue."
    end

    test "validates required configuration" do
      # Should not raise for properly configured app
      assert :ok = Config.validate_config!(:my_app)

      # Test that it would raise for missing config (conceptually)
      # We can't easily test this without mocking Application.get_env
    end

    test "provides route helpers" do
      # Applications use these to get configured routes
      assert Config.sign_in_url(:my_app) == "/sign-in"
      assert Config.after_sign_in_url(:my_app) == "/dashboard"
      assert Config.after_sign_out_url(:my_app) == "/"
    end

    test "provides message helpers" do
      # Applications use these for consistent messaging
      assert Config.auth_required_message(:my_app) == "Please sign in to continue."
      assert Config.session_expired_message(:my_app) == "Your session has expired. Please sign in again."
      assert Config.auth_required_json_message(:my_app) == "Authentication required"
    end

    test "provides JavaScript configuration" do
      js_config = Config.for_javascript(:my_app)

      # Frontend JavaScript relies on this structure
      assert js_config.publishableKey == "pk_test"
      assert js_config.frontendApiUrl == "https://test.clerk.dev"
      assert js_config.routes.sign_in == "/sign-in"
      assert js_config.elements.user_button == "clerk-user-button"
    end

    test "includes identity mapping configuration" do
      config = Config.get_config(:my_app)

      # Applications can customize identity extraction
      assert config.identity_mapping.subject_field == ["sub", :sub, "id", :id, "user_id", :user_id]
      assert config.identity_mapping.email_field == ["email", :email, "primary_email_address", :primary_email_address]
    end
  end
end