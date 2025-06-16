defmodule ClerkPhoenix.Security.Config do
  @moduledoc """
  Security configuration management for ClerkPhoenix.

  Provides centralized configuration for security features including:
  - Rate limiting settings
  - Session security parameters
  - Input validation rules
  - Security monitoring thresholds
  """

  @default_security_config %{
    rate_limiting: %{
      enabled: true,
      window_ms: 60_000,  # 1 minute
      max_requests: 10,
      cleanup_interval_ms: 300_000  # 5 minutes
    },
    session_security: %{
      fingerprint_enabled: true,
      ip_validation: true,
      user_agent_validation: true,
      session_timeout_hours: 24,
      max_concurrent_sessions: 5,
      rotation_interval: 4 * 60 * 60,  # 4 hours
      max_session_keys: 50,
      max_session_value_size: 10_000
    },
    input_validation: %{
      max_email_length: 254,
      max_token_length: 8192,
      max_param_length: 1024,
      sanitize_inputs: true
    },
    monitoring: %{
      enabled: true,
      log_successful_auth: true,
      log_failed_auth: true,
      alert_on_brute_force: true,
      brute_force_threshold: 5,
      analysis_window_minutes: 15
    },
    headers: %{
      content_type_options: "nosniff",
      frame_options: "DENY",
      xss_protection: "1; mode=block",
      referrer_policy: "strict-origin-when-cross-origin",
      permissions_policy: "camera=(), microphone=(), geolocation=()"
    }
  }

  @doc """
  Gets the complete security configuration for the given OTP app.

  ## Examples

      iex> ClerkPhoenix.Security.Config.get_config(:my_app)
      %{
        rate_limiting: %{enabled: true, ...},
        session_security: %{fingerprint_enabled: true, ...},
        ...
      }
  """
  def get_config(otp_app) do
    otp_app
    |> get_raw_security_config()
    |> merge_defaults()
  end

  @doc """
  Gets a specific security configuration value.

  ## Examples

      iex> ClerkPhoenix.Security.Config.get(:my_app, [:rate_limiting, :enabled])
      true

      iex> ClerkPhoenix.Security.Config.get(:my_app, :session_security)
      %{fingerprint_enabled: true, ...}
  """
  def get(otp_app, key_or_path) do
    config = get_config(otp_app)
    get_nested(config, key_or_path)
  end

  # Rate limiting configuration

  @doc """
  Gets rate limiting configuration.
  """
  def rate_limiting_config(otp_app), do: get(otp_app, :rate_limiting)

  @doc """
  Checks if rate limiting is enabled.
  """
  def rate_limiting_enabled?(otp_app), do: get(otp_app, [:rate_limiting, :enabled])

  @doc """
  Gets the rate limiting window in milliseconds.
  """
  def rate_limiting_window_ms(otp_app), do: get(otp_app, [:rate_limiting, :window_ms])

  @doc """
  Gets the maximum requests allowed in the rate limiting window.
  """
  def rate_limiting_max_requests(otp_app), do: get(otp_app, [:rate_limiting, :max_requests])

  # Session security configuration

  @doc """
  Gets session security configuration.
  """
  def session_security_config(otp_app), do: get(otp_app, :session_security)

  @doc """
  Checks if session fingerprinting is enabled.
  """
  def session_fingerprint_enabled?(otp_app), do: get(otp_app, [:session_security, :fingerprint_enabled])

  @doc """
  Checks if IP validation is enabled for sessions.
  """
  def session_ip_validation_enabled?(otp_app), do: get(otp_app, [:session_security, :ip_validation])

  @doc """
  Checks if User-Agent validation is enabled for sessions.
  """
  def session_user_agent_validation_enabled?(otp_app), do: get(otp_app, [:session_security, :user_agent_validation])

  @doc """
  Gets the session timeout in hours.
  """
  def session_timeout_hours(otp_app), do: get(otp_app, [:session_security, :session_timeout_hours])

  @doc """
  Gets the maximum number of concurrent sessions allowed per user.
  """
  def max_concurrent_sessions(otp_app), do: get(otp_app, [:session_security, :max_concurrent_sessions])

  # Input validation configuration

  @doc """
  Gets input validation configuration.
  """
  def input_validation_config(otp_app), do: get(otp_app, :input_validation)

  @doc """
  Gets the maximum allowed email length.
  """
  def max_email_length(otp_app), do: get(otp_app, [:input_validation, :max_email_length])

  @doc """
  Gets the maximum allowed token length.
  """
  def max_token_length(otp_app), do: get(otp_app, [:input_validation, :max_token_length])

  @doc """
  Gets the maximum allowed parameter length.
  """
  def max_param_length(otp_app), do: get(otp_app, [:input_validation, :max_param_length])

  @doc """
  Checks if input sanitization is enabled.
  """
  def sanitize_inputs?(otp_app), do: get(otp_app, [:input_validation, :sanitize_inputs])

  # Monitoring configuration

  @doc """
  Gets monitoring configuration.
  """
  def monitoring_config(otp_app), do: get(otp_app, :monitoring)

  @doc """
  Checks if security monitoring is enabled.
  """
  def monitoring_enabled?(otp_app), do: get(otp_app, [:monitoring, :enabled])

  @doc """
  Checks if successful authentication events should be logged.
  """
  def log_successful_auth?(otp_app), do: get(otp_app, [:monitoring, :log_successful_auth])

  @doc """
  Checks if failed authentication events should be logged.
  """
  def log_failed_auth?(otp_app), do: get(otp_app, [:monitoring, :log_failed_auth])

  @doc """
  Checks if brute force alerts are enabled.
  """
  def alert_on_brute_force?(otp_app), do: get(otp_app, [:monitoring, :alert_on_brute_force])

  @doc """
  Gets the brute force detection threshold.
  """
  def brute_force_threshold(otp_app), do: get(otp_app, [:monitoring, :brute_force_threshold])

  @doc """
  Gets the analysis window in minutes for security monitoring.
  """
  def analysis_window_minutes(otp_app), do: get(otp_app, [:monitoring, :analysis_window_minutes])

  # Security headers configuration

  @doc """
  Gets security headers configuration.
  """
  def headers_config(otp_app), do: get(otp_app, :headers)

  @doc """
  Gets the X-Content-Type-Options header value.
  """
  def content_type_options_header(otp_app), do: get(otp_app, [:headers, :content_type_options])

  @doc """
  Gets the X-Frame-Options header value.
  """
  def frame_options_header(otp_app), do: get(otp_app, [:headers, :frame_options])

  @doc """
  Gets the X-XSS-Protection header value.
  """
  def xss_protection_header(otp_app), do: get(otp_app, [:headers, :xss_protection])

  @doc """
  Gets the Referrer-Policy header value.
  """
  def referrer_policy_header(otp_app), do: get(otp_app, [:headers, :referrer_policy])

  @doc """
  Gets the Permissions-Policy header value.
  """
  def permissions_policy_header(otp_app), do: get(otp_app, [:headers, :permissions_policy])

  # Validation functions

  @doc """
  Validates that security configuration is properly set up.

  ## Examples

      iex> ClerkPhoenix.Security.Config.validate_config!(:my_app)
      :ok

      # Raises if configuration is invalid
      iex> ClerkPhoenix.Security.Config.validate_config!(:my_app)
      ** (RuntimeError) Invalid security configuration: rate_limiting window_ms must be positive
  """
  def validate_config!(otp_app) do
    config = get_config(otp_app)

    # Validate rate limiting config
    validate_rate_limiting_config!(config.rate_limiting)

    # Validate session security config
    validate_session_security_config!(config.session_security)

    # Validate input validation config
    validate_input_validation_config!(config.input_validation)

    # Validate monitoring config
    validate_monitoring_config!(config.monitoring)

    :ok
  end

  @doc """
  Gets security configuration formatted for JavaScript consumption.

  This returns only the configuration that's safe to expose to the frontend.

  ## Examples

      iex> ClerkPhoenix.Security.Config.for_javascript(:my_app)
      %{
        rateLimiting: %{enabled: true},
        inputValidation: %{maxEmailLength: 254}
      }
  """
  def for_javascript(otp_app) do
    config = get_config(otp_app)

    %{
      rateLimiting: %{
        enabled: config.rate_limiting.enabled
      },
      inputValidation: %{
        maxEmailLength: config.input_validation.max_email_length,
        maxParamLength: config.input_validation.max_param_length
      }
    }
  end

  # Private functions

  defp get_raw_security_config(otp_app) do
    case Application.get_env(otp_app, ClerkPhoenix) do
      nil -> %{}
      config when is_list(config) ->
        config
        |> Enum.into(%{})
        |> Map.get(:security, %{})
      config when is_map(config) ->
        Map.get(config, :security, %{})
    end
  end

  defp merge_defaults(config) when is_map(config) do
    deep_merge(@default_security_config, config)
  end

  defp merge_defaults(config) when is_list(config) do
    config
    |> Enum.into(%{})
    |> merge_defaults()
  end

  defp deep_merge(left, right) when is_map(left) and is_map(right) do
    Map.merge(left, right, fn _key, left_val, right_val ->
      deep_merge(left_val, right_val)
    end)
  end

  defp deep_merge(_left, right), do: right

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

  # Validation helpers

  defp validate_rate_limiting_config!(config) do
    unless is_boolean(config.enabled) do
      raise "Invalid security configuration: rate_limiting enabled must be boolean"
    end

    unless is_integer(config.window_ms) and config.window_ms > 0 do
      raise "Invalid security configuration: rate_limiting window_ms must be positive integer"
    end

    unless is_integer(config.max_requests) and config.max_requests > 0 do
      raise "Invalid security configuration: rate_limiting max_requests must be positive integer"
    end
  end

  defp validate_session_security_config!(config) do
    unless is_boolean(config.fingerprint_enabled) do
      raise "Invalid security configuration: session_security fingerprint_enabled must be boolean"
    end

    unless is_boolean(config.ip_validation) do
      raise "Invalid security configuration: session_security ip_validation must be boolean"
    end

    unless is_boolean(config.user_agent_validation) do
      raise "Invalid security configuration: session_security user_agent_validation must be boolean"
    end

    unless is_integer(config.session_timeout_hours) and config.session_timeout_hours > 0 do
      raise "Invalid security configuration: session_security session_timeout_hours must be positive integer"
    end

    unless is_integer(config.max_concurrent_sessions) and config.max_concurrent_sessions > 0 do
      raise "Invalid security configuration: session_security max_concurrent_sessions must be positive integer"
    end
  end

  defp validate_input_validation_config!(config) do
    unless is_integer(config.max_email_length) and config.max_email_length > 0 do
      raise "Invalid security configuration: input_validation max_email_length must be positive integer"
    end

    unless is_integer(config.max_token_length) and config.max_token_length > 0 do
      raise "Invalid security configuration: input_validation max_token_length must be positive integer"
    end

    unless is_integer(config.max_param_length) and config.max_param_length > 0 do
      raise "Invalid security configuration: input_validation max_param_length must be positive integer"
    end

    unless is_boolean(config.sanitize_inputs) do
      raise "Invalid security configuration: input_validation sanitize_inputs must be boolean"
    end
  end

  defp validate_monitoring_config!(config) do
    unless is_boolean(config.enabled) do
      raise "Invalid security configuration: monitoring enabled must be boolean"
    end

    unless is_boolean(config.log_successful_auth) do
      raise "Invalid security configuration: monitoring log_successful_auth must be boolean"
    end

    unless is_boolean(config.log_failed_auth) do
      raise "Invalid security configuration: monitoring log_failed_auth must be boolean"
    end

    unless is_boolean(config.alert_on_brute_force) do
      raise "Invalid security configuration: monitoring alert_on_brute_force must be boolean"
    end

    unless is_integer(config.brute_force_threshold) and config.brute_force_threshold > 0 do
      raise "Invalid security configuration: monitoring brute_force_threshold must be positive integer"
    end

    unless is_integer(config.analysis_window_minutes) and config.analysis_window_minutes > 0 do
      raise "Invalid security configuration: monitoring analysis_window_minutes must be positive integer"
    end
  end
end
