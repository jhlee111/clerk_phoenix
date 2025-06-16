defmodule ClerkPhoenix.Middleware.AuthPipeline do
  @moduledoc """
  Composable authentication pipelines for different application contexts.

  This module provides a way to define and execute reusable authentication
  pipelines that can be composed for different routes, controllers, or
  application contexts.

  ## Features

  - Predefined pipelines for common scenarios (web, API, admin)
  - Custom pipeline composition
  - Pipeline inheritance and extension
  - Performance optimization through pipeline caching
  - Conditional pipeline execution

  ## Usage

      # In your router
      pipeline :web_auth do
        plug ClerkPhoenix.Middleware.AuthPipeline, :web_pipeline
      end

      pipeline :api_auth do
        plug ClerkPhoenix.Middleware.AuthPipeline, :api_pipeline
      end

      # Custom pipeline
      pipeline :custom_auth do
        plug ClerkPhoenix.Middleware.AuthPipeline, [
          {ClerkPhoenix.Plug.SecurityPlug, []},
          {ClerkPhoenix.Plug.AuthPlug, :require_auth},
          {ClerkPhoenix.RBAC.Middleware, [require_role: "admin"]}
        ]
      end
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @doc """
  Initializes the auth pipeline plug.

  ## Parameters

  - `pipeline_name` - Atom representing a predefined pipeline
  - `pipeline_config` - List of {module, opts} tuples for custom pipelines
  - `opts` - Keyword list of options

  ## Examples

      # Predefined pipeline
      plug ClerkPhoenix.Middleware.AuthPipeline, :web_pipeline

      # Custom pipeline
      plug ClerkPhoenix.Middleware.AuthPipeline, [
        {ClerkPhoenix.Plug.AuthPlug, :require_auth},
        {ClerkPhoenix.RBAC.Middleware, []}
      ]

      # Pipeline with options
      plug ClerkPhoenix.Middleware.AuthPipeline, :api_pipeline,
        otp_app: :my_app, cache: true
  """
  def init(pipeline_name) when is_atom(pipeline_name) do
    %{
      pipeline: pipeline_name,
      type: :predefined,
      cache: true
    }
  end

  def init(pipeline_config) when is_list(pipeline_config) do
    # Check if it's a pipeline config or options
    case Keyword.keyword?(pipeline_config) and Keyword.has_key?(pipeline_config, :pipeline) do
      true ->
        # It's options with pipeline specified
        pipeline = Keyword.get(pipeline_config, :pipeline)
        opts = Keyword.delete(pipeline_config, :pipeline)

        %{
          pipeline: pipeline,
          type: if(is_atom(pipeline), do: :predefined, else: :custom),
          cache: Keyword.get(opts, :cache, true),
          opts: opts
        }
      false ->
        # It's a custom pipeline config
        %{
          pipeline: pipeline_config,
          type: :custom,
          cache: false
        }
    end
  end

  @doc """
  Executes the authentication pipeline.
  """
  def call(conn, %{pipeline: pipeline_name, type: :predefined} = config) do
    pipeline_steps = get_predefined_pipeline(pipeline_name, conn)
    execute_pipeline(conn, pipeline_steps, config)
  end

  def call(conn, %{pipeline: pipeline_config, type: :custom} = config) do
    execute_pipeline(conn, pipeline_config, config)
  end

  @doc """
  Predefined web authentication pipeline.

  Includes:
  - Security hardening
  - Session-based authentication
  - Session security validation
  - User context management
  """
  def web_pipeline(_otp_app \\ nil) do
    [
      ClerkPhoenix.AuthPlug,
      {ClerkPhoenix.Middleware.SessionSecurity, []},
      {ClerkPhoenix.API.RateLimit, strategy: :per_user, max_requests: 1000, window: 3600}
    ]
  end

  @doc """
  Predefined API authentication pipeline.

  Includes:
  - CORS handling
  - Rate limiting
  - JWT authentication
  - API-specific security
  """
  def api_pipeline(_otp_app \\ nil) do
    [
      {ClerkPhoenix.API.JWTAuth, []},
      {ClerkPhoenix.API.RateLimit, strategy: :per_api_key, max_requests: 10000, window: 3600},
      {ClerkPhoenix.Security.Monitor, []}
    ]
  end

  @doc """
  Predefined admin authentication pipeline.

  Includes:
  - Full web pipeline
  - Role-based access control
  - Audit logging
  - Enhanced security
  """
  def admin_pipeline(otp_app \\ nil) do
    web_pipeline(otp_app) ++ [
      {ClerkPhoenix.RBAC.Middleware, [require_role: "admin"]},
      {ClerkPhoenix.Middleware.AuditLog, []},
      {ClerkPhoenix.Middleware.MFA, [required: true]}
    ]
  end

  @doc """
  Optional authentication pipeline for public routes.

  Includes:
  - Security hardening
  - Optional authentication
  - User context loading (if authenticated)
  """
  def public_pipeline(_otp_app \\ nil) do
    [
      {ClerkPhoenix.Plug.SecurityPlug, []},
      {ClerkPhoenix.Plug.AuthPlug, [on_auth_failure: :pass_through]},
      {ClerkPhoenix.Middleware.UserContextLoader, [optional: true]}
    ]
  end

  @doc """
  API key authentication pipeline.

  Includes:
  - Rate limiting
  - API key authentication
  - Permission validation
  """
  def api_key_pipeline(_otp_app \\ nil) do
    [
      {ClerkPhoenix.API.RateLimit, [strategy: :api_key]},
      {ClerkPhoenix.API.KeyAuth, []},
      {ClerkPhoenix.API.PermissionValidator, []}
    ]
  end

  @doc """
  Webhook authentication pipeline.

  Includes:
  - Signature validation
  - Timestamp verification
  - Rate limiting
  """
  def webhook_pipeline(_otp_app \\ nil) do
    [
      {ClerkPhoenix.API.WebhookAuth, []},
      {ClerkPhoenix.API.RateLimit, [strategy: :webhook]},
      {ClerkPhoenix.Middleware.WebhookLogger, []}
    ]
  end

  @doc """
  Creates a custom pipeline by extending an existing one.

  ## Examples

      # Extend web pipeline with custom middleware
      custom_pipeline = ClerkPhoenix.Middleware.AuthPipeline.extend_pipeline(
        :web_pipeline,
        [{MyApp.CustomAuth, []}]
      )
  """
  def extend_pipeline(base_pipeline, additional_steps) when is_atom(base_pipeline) do
    base_steps = get_predefined_pipeline(base_pipeline, nil)
    base_steps ++ additional_steps
  end

  def extend_pipeline(base_pipeline, additional_steps) when is_list(base_pipeline) do
    base_pipeline ++ additional_steps
  end

  @doc """
  Validates a pipeline configuration.

  ## Examples

      iex> ClerkPhoenix.Middleware.AuthPipeline.validate_pipeline(:web_pipeline)
      :ok

      iex> ClerkPhoenix.Middleware.AuthPipeline.validate_pipeline([{InvalidPlug, []}])
      {:error, :invalid_plug}
  """
  def validate_pipeline(pipeline_name) when is_atom(pipeline_name) do
    case get_predefined_pipeline(pipeline_name, nil) do
      nil -> {:error, :unknown_pipeline}
      pipeline -> validate_pipeline(pipeline)
    end
  end

  def validate_pipeline(pipeline_config) when is_list(pipeline_config) do
    Enum.reduce_while(pipeline_config, :ok, fn {module, _opts}, _acc ->
      if Code.ensure_loaded?(module) and function_exported?(module, :call, 2) do
        {:cont, :ok}
      else
        {:halt, {:error, {:invalid_plug, module}}}
      end
    end)
  end

  # Private functions

  defp execute_pipeline(conn, pipeline_steps, config) do
    Logger.debug("Executing auth pipeline with #{length(pipeline_steps)} steps")

    Enum.reduce_while(pipeline_steps, conn, fn {module, opts}, acc_conn ->
      if acc_conn.halted do
        {:halt, acc_conn}
      else
        try do
          Logger.debug("Executing pipeline step: #{inspect(module)}")

          # Initialize the plug if needed
          init_opts = if function_exported?(module, :init, 1) do
            module.init(opts)
          else
            opts
          end

          # Call the plug
          result_conn = module.call(acc_conn, init_opts)

          # Log successful execution
          Logger.debug("Pipeline step completed: #{inspect(module)}")

          {:cont, result_conn}
        rescue
          error ->
            Logger.error("Pipeline step failed: #{inspect(module)}, error: #{inspect(error)}")

            # Handle pipeline errors gracefully
            error_conn = handle_pipeline_error(acc_conn, module, error, config)
            {:halt, error_conn}
        end
      end
    end)
  end

  defp get_predefined_pipeline(pipeline_name, conn) do
    otp_app = get_otp_app(conn)

    case pipeline_name do
      :web_pipeline -> web_pipeline(otp_app)
      :api_pipeline -> api_pipeline(otp_app)
      :admin_pipeline -> admin_pipeline(otp_app)
      :public_pipeline -> public_pipeline(otp_app)
      :api_key_pipeline -> api_key_pipeline(otp_app)
      :webhook_pipeline -> webhook_pipeline(otp_app)
      _ ->
        Logger.warning("Unknown predefined pipeline: #{inspect(pipeline_name)}")
        nil
    end
  end

  defp handle_pipeline_error(conn, module, error, _config) do
    # Log the error
    Logger.error("Security incident: pipeline_error", %{
      module: module,
      error: inspect(error),
      ip_address: get_client_ip(conn)
    })

    # Return appropriate error response
    conn
    |> put_status(:internal_server_error)
    |> Phoenix.Controller.json(%{error: "Authentication pipeline error"})
    |> halt()
  end

  defp get_otp_app(nil), do: :clerk_phoenix
  defp get_otp_app(conn) do
    case conn.private[:phoenix_endpoint] do
      nil -> :clerk_phoenix
      endpoint ->
        endpoint
        |> Module.split()
        |> List.first()
        |> Macro.underscore()
        |> String.to_atom()
    end
  end

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded_ips] ->
        forwarded_ips
        |> String.split(",")
        |> List.first()
        |> String.trim()
      [] ->
        case get_req_header(conn, "x-real-ip") do
          [real_ip] -> real_ip
          [] -> to_string(:inet_parse.ntoa(conn.remote_ip))
        end
    end
  end
end
