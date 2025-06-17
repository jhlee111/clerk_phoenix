defmodule ClerkPhoenix.Config do
  @moduledoc """
  Configuration helpers for ClerkPhoenix.

  This module provides centralized configuration management with smart defaults
  and validation for Clerk authentication settings.
  """

  @required_keys [:publishable_key, :secret_key, :frontend_api_url]

  @default_config %{
    api_url: "https://api.clerk.com",
    routes: %{
      sign_in: "/sign-in",
      sign_out: "/sign-out",
      after_sign_in: "/dashboard",
      after_sign_up: "/onboard",
      after_sign_out: "/",
      home: "/"
    },
    messages: %{
      auth_required: "Please sign in to continue.",
      auth_required_json: "Authentication required",
      session_expired: "Your session has expired. Please sign in again."
    },
    elements: %{
      user_button: "clerk-user-button",
      sign_in: "clerk-sign-in",
      sign_up: "clerk-sign-up"
    },
    identity_mapping: %{
      subject_field: ["sub", :sub, "id", :id, "user_id", :user_id],
      email_field: ["email", :email, "primary_email_address", :primary_email_address],
      first_name_field: ["given_name", :given_name, "first_name", :first_name],
      last_name_field: ["family_name", :family_name, "last_name", :last_name],
      name_field: ["name", :name, "full_name", :full_name],
      image_field: ["picture", :picture, "image_url", :image_url, "avatar", :avatar],
      organizations_field: ["org", :org, "organizations", :organizations, "orgs", :orgs]
    }
  }

  @doc """
  Gets the complete configuration for the given OTP app.

  ## Examples

      iex> ClerkPhoenix.Config.get_config(:my_app)
      %{
        publishable_key: "pk_...",
        secret_key: "sk_...",
        frontend_api_url: "https://...",
        routes: %{...},
        messages: %{...}
      }
  """
  def get_config(otp_app) do
    otp_app
    |> get_raw_config()
    |> merge_defaults()
  end

  @doc """
  Gets a specific configuration value.

  ## Examples

      iex> ClerkPhoenix.Config.get(:my_app, :publishable_key)
      "pk_test_..."

      iex> ClerkPhoenix.Config.get(:my_app, [:routes, :sign_in])
      "/sign-in"
  """
  def get(otp_app, key_or_path) do
    config = get_config(otp_app)
    get_nested(config, key_or_path)
  end

  @doc """
  Gets the publishable key for the given OTP app.
  """
  def publishable_key(otp_app), do: get(otp_app, :publishable_key)

  @doc """
  Gets the secret key for the given OTP app.
  """
  def secret_key(otp_app), do: get(otp_app, :secret_key)

  @doc """
  Gets the frontend API URL for the given OTP app.
  """
  def frontend_api_url(otp_app), do: get(otp_app, :frontend_api_url)

  @doc """
  Gets the API URL for the given OTP app.
  """
  def api_url(otp_app), do: get(otp_app, :api_url)

  @doc """
  Gets the expected audience for JWT validation for the given OTP app.
  """
  def expected_audience(otp_app), do: get(otp_app, :expected_audience)

  @doc """
  Gets the sign-in URL for the given OTP app.
  """
  def sign_in_url(otp_app), do: get(otp_app, [:routes, :sign_in])

  @doc """
  Gets the sign-out URL for the given OTP app.
  """
  def sign_up_url(otp_app), do: get(otp_app, [:routes, :sign_up])

  @doc """
  Gets the after sign-in URL for the given OTP app.
  """
  def after_sign_in_url(otp_app), do: get(otp_app, [:routes, :after_sign_in])

  @doc """
  Gets the after sign-up URL for the given OTP app.
  """
  def after_sign_up_url(otp_app), do: get(otp_app, [:routes, :after_sign_up])

  @doc """
  Gets the after sign-out URL for the given OTP app.
  """
  def after_sign_out_url(otp_app), do: get(otp_app, [:routes, :after_sign_out])

  @doc """
  Gets the auth required message for the given OTP app.
  """
  def auth_required_message(otp_app), do: get(otp_app, [:messages, :auth_required])

  @doc """
  Gets the auth required JSON message for the given OTP app.
  """
  def auth_required_json_message(otp_app), do: get(otp_app, [:messages, :auth_required_json])

  @doc """
  Gets the session expired message for the given OTP app.
  """
  def session_expired_message(otp_app), do: get(otp_app, [:messages, :session_expired])

  @doc """
  Gets configuration formatted for JavaScript consumption.

  This is used to pass configuration to the frontend Clerk.js integration.

  ## Examples

      iex> ClerkPhoenix.Config.for_javascript(:my_app)
      %{
        publishableKey: "pk_...",
        frontendApiUrl: "https://...",
        routes: %{...},
        elements: %{...}
      }
  """
  def get_clerk_javascript_config(otp_app) do
    %{
      signInUrl: sign_in_url(otp_app),
      signUpUrl: sign_up_url(otp_app),
      signInFallbackRedirectUrl: after_sign_in_url(otp_app),
      signUpFallbackRedirectUrl: after_sign_up_url(otp_app),
      afterSignOutUrl: after_sign_out_url(otp_app)
    }
    |> JSON.encode!()
  end

  @doc """
  Validates that all required configuration is present.

  Raises an exception if any required configuration is missing.

  ## Examples

      iex> ClerkPhoenix.Config.validate_config!(:my_app)
      :ok

      # Raises if configuration is missing
      iex> ClerkPhoenix.Config.validate_config!(:my_app)
      ** (RuntimeError) Missing required ClerkPhoenix configuration: [:publishable_key]
  """
  def validate_config!(otp_app) do
    config = get_raw_config(otp_app)

    missing_keys =
      @required_keys
      |> Enum.filter(fn key ->
        case Map.get(config, key) do
          nil -> true
          "" -> true
          _ -> false
        end
      end)

    if missing_keys != [] do
      raise "Missing required ClerkPhoenix configuration for #{otp_app}: #{inspect(missing_keys)}. " <>
              "Please ensure the following environment variables are set: " <>
              "CLERK_PUBLISHABLE_KEY, CLERK_SECRET_KEY, CLERK_FRONTEND_API_URL"
    end

    :ok
  end

  # Private functions

  defp get_raw_config(otp_app) do
    case Application.get_env(otp_app, ClerkPhoenix) do
      nil ->
        raise "No ClerkPhoenix configuration found for #{otp_app}. " <>
                "Please add ClerkPhoenix configuration to your config files."

      config when is_list(config) ->
        Enum.into(config, %{})

      config when is_map(config) ->
        config
    end
  end

  defp merge_defaults(config) do
    Map.merge(@default_config, config)
  end

  defp get_nested(config, key) when is_atom(key) do
    Map.get(config, key)
  end

  defp get_nested(config, [key]) do
    Map.get(config, key)
  end

  defp get_nested(config, [key | rest]) do
    case Map.get(config, key) do
      nil -> nil
      nested_config -> get_nested(nested_config, rest)
    end
  end
end
