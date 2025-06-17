defmodule ClerkPhoenix.JWT do
  @moduledoc """
  Secure JWT validation using proper cryptographic verification.

  Implements Clerk-specific JWT validation with JWKS key verification.
  Includes comprehensive error handling and detailed logging for debugging.
  """

  use Joken.Config
  require Logger

  @jwks_cache_ttl 30 * 60 * 1000  # 30 minutes in milliseconds
  @jwks_cache_name :clerk_jwks_cache

  @doc """
  Validates a Clerk JWT token with proper signature verification.

  ## Parameters
  - `token` - The JWT token string
  - `otp_app` - The OTP application for configuration
  - `opts` - Additional options (optional)

  ## Returns
  - `{:ok, claims}` - Valid token with claims
  - `{:error, reason}` - Invalid token with reason

  ## Examples

      iex> ClerkPhoenix.JWT.validate_token("eyJ...", :my_app)
      {:ok, %{"sub" => "user_123", "exp" => 1234567890, ...}}

      iex> ClerkPhoenix.JWT.validate_token("invalid", :my_app)
      {:error, :invalid_token_format}
  """
  def validate_token(token, otp_app, opts \\ []) do
    token_preview = String.slice(token, 0, 20) <> "..."
    Logger.debug("Starting JWT validation for token: #{token_preview}")

    with {:ok, header} <- decode_header(token),
         {:ok, jwks} <- get_jwks(otp_app, opts),
         {:ok, key} <- find_matching_key(header, jwks),
         {:ok, claims} <- verify_token_with_key(token, key),
         :ok <- validate_claims(claims, otp_app, opts),
         :ok <- check_blacklist(claims) do
      Logger.debug("JWT validation successful for token: #{token_preview}")
      {:ok, claims}
    else
      {:error, reason} = error ->
        log_detailed_jwt_failure(reason, token, otp_app, opts)
        error
      error ->
        Logger.error("Unexpected JWT validation error: #{inspect(error)}",
          token_preview: token_preview
        )
        {:error, :jwt_validation_failed}
    end
  end

  @doc """
  Validates JWT claims specific to Clerk tokens.
  """
  def validate_claims(claims, otp_app, opts \\ []) do
    with :ok <- validate_expiration(claims),
         :ok <- validate_issued_at(claims),
         :ok <- validate_audience(claims, otp_app, opts),
         :ok <- validate_issuer(claims, otp_app, opts),
         :ok <- validate_required_claims(claims) do
      :ok
    else
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Checks if a token is in the blacklist (revoked).
  """
  def token_blacklisted?(jti) when is_binary(jti) do
    ClerkPhoenix.TokenBlacklist.blacklisted?(jti)
  end

  def token_blacklisted?(_), do: false

  # Private functions

  defp decode_header(token) when is_binary(token) do
    case String.split(token, ".") do
      [header_b64, _payload_b64, _signature_b64] ->
        try do
          header_json = Base.decode64!(header_b64, padding: false)
          header = JSON.decode!(header_json)
          {:ok, header}
        rescue
          _ -> {:error, :invalid_header}
        end
      _ ->
        {:error, :invalid_token_format}
    end
  end

  defp get_jwks(otp_app, opts) do
    frontend_api_url =
      Keyword.get(opts, :clerk_frontend_api_url) ||
      ClerkPhoenix.Config.frontend_api_url(otp_app)

    if is_nil(frontend_api_url) do
      {:error, :missing_frontend_api_url}
    else
      jwks_url = "#{frontend_api_url}/.well-known/jwks.json"
      fetch_jwks_with_cache(jwks_url)
    end
  end

  defp fetch_jwks_with_cache(jwks_url) do
    cache_key = {:jwks, jwks_url}
    current_time = System.monotonic_time(:millisecond)

    case :ets.lookup(@jwks_cache_name, cache_key) do
      [{^cache_key, jwks, expiry}] when expiry > current_time ->
        Logger.debug("Using cached JWKS for #{jwks_url}")
        {:ok, jwks}
      _ ->
        fetch_and_cache_jwks(jwks_url, cache_key)
    end
  rescue
    ArgumentError ->
      # ETS table doesn't exist, create it and retry
      create_jwks_cache()
      fetch_jwks_with_cache(jwks_url)
  end

  defp create_jwks_cache do
    try do
      :ets.new(@jwks_cache_name, [:named_table, :public, read_concurrency: true])
    rescue
      ArgumentError ->
        # Table already exists, ignore
        :ok
    end
  end

  defp fetch_and_cache_jwks(jwks_url, cache_key) do
    Logger.debug("Fetching JWKS from #{jwks_url}")

    case Req.get(jwks_url, receive_timeout: 10_000) do
      {:ok, %{status: 200, body: jwks}} ->
        expiry = System.monotonic_time(:millisecond) + @jwks_cache_ttl
        :ets.insert(@jwks_cache_name, {cache_key, jwks, expiry})
        {:ok, jwks}

      {:ok, %{status: status}} ->
        Logger.error("JWKS fetch failed with status: #{status}")
        {:error, :jwks_fetch_failed}

      {:error, reason} ->
        Logger.error("JWKS fetch error: #{inspect(reason)}")
        {:error, :jwks_request_failed}
    end
  end

  defp find_matching_key(header, jwks) do
    kid = Map.get(header, "kid")

    if is_nil(kid) do
      {:error, :missing_key_id}
    else
      case find_key_by_id(jwks, kid) do
        nil ->
          Logger.debug("No key found for kid: #{kid}")
          Logger.debug("Available keys: #{inspect(Map.get(jwks, "keys", []) |> Enum.map(&Map.get(&1, "kid")))}")
          {:error, :key_not_found}
        key ->
          Logger.debug("Found matching key for kid: #{kid}")
          Logger.debug("Key details: #{inspect(Map.take(key, ["kty", "alg", "use", "kid"]))}")
          {:ok, key}
      end
    end
  end

  defp find_key_by_id(%{"keys" => keys}, kid) when is_list(keys) do
    Enum.find(keys, fn key -> Map.get(key, "kid") == kid end)
  end

  defp find_key_by_id(_, _), do: nil

  defp verify_token_with_key(token, key) do
    try do
      Logger.debug("Creating Joken signer from JWK")

      # Get the algorithm from the JWK or use RS256 as default
      algorithm = Map.get(key, "alg", "RS256")
      Logger.debug("Using algorithm: #{algorithm}")

      # Create Joken signer directly from JWK
      signer = Joken.Signer.create(algorithm, key)
      Logger.debug("Created Joken signer with #{algorithm}")

      case Joken.verify(token, signer) do
        {:ok, claims} ->
          Logger.debug("JWT verification successful with #{algorithm}")
          {:ok, claims}
        {:error, reason} ->
          Logger.debug("Joken verification failed with #{algorithm}: #{inspect(reason)}")
          {:error, reason}
      end
    rescue
      error ->
        Logger.error("Token verification error: #{inspect(error)}")
        Logger.debug("Key that caused error: #{inspect(key)}")
        {:error, :signature_verification_failed}
    end
  end

  defp validate_expiration(%{"exp" => exp}) when is_integer(exp) do
    current_time = System.system_time(:second)

    if exp > current_time do
      :ok
    else
      {:error, :token_expired}
    end
  end

  defp validate_expiration(_), do: {:error, :missing_expiration}

  defp validate_issued_at(%{"iat" => iat}) when is_integer(iat) do
    current_time = System.system_time(:second)
    # Allow 5 minutes leeway for clock skew
    leeway = 5 * 60

    if iat <= current_time + leeway do
      :ok
    else
      {:error, :token_not_yet_valid}
    end
  end

  defp validate_issued_at(_), do: {:error, :missing_issued_at}

  defp validate_audience(%{"azp" => azp}, otp_app, opts) do
    # Clerk uses "azp" (authorized party) claim instead of standard "aud"
    expected_audience =
      Keyword.get(opts, :expected_audience) ||
      ClerkPhoenix.Config.expected_audience(otp_app)

    cond do
      is_nil(expected_audience) -> :ok  # Skip validation if not configured
      azp == expected_audience -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp validate_audience(_, _, _), do: :ok  # Audience validation is optional

  defp validate_issuer(%{"iss" => iss}, otp_app, opts) do
    frontend_api_url =
      Keyword.get(opts, :clerk_frontend_api_url) ||
      ClerkPhoenix.Config.frontend_api_url(otp_app)

    if is_nil(frontend_api_url) or iss == frontend_api_url do
      :ok
    else
      {:error, :invalid_issuer}
    end
  end

  defp validate_issuer(_, _, _), do: {:error, :missing_issuer}

  defp validate_required_claims(%{"sub" => sub}) when is_binary(sub) and sub != "" do
    :ok
  end

  defp validate_required_claims(_), do: {:error, :missing_required_claims}

  defp check_blacklist(%{"jti" => jti}) when is_binary(jti) do
    if token_blacklisted?(jti) do
      {:error, :token_blacklisted}
    else
      :ok
    end
  end

  defp check_blacklist(_), do: :ok  # No JTI claim, skip blacklist check

  # Private function for detailed JWT failure logging
  defp log_detailed_jwt_failure(reason, token, otp_app, opts) do
    token_preview = String.slice(token, 0, 20) <> "..."

    case reason do
      :token_expired ->
        # Try to extract expiration details
        case decode_header(token) do
          {:ok, _header} ->
            case String.split(token, ".") do
              [_header_b64, payload_b64, _signature_b64] ->
                try do
                  payload_json = Base.decode64!(payload_b64, padding: false)
                  claims = JSON.decode!(payload_json)

                  exp = claims["exp"]
                  current_time = System.system_time(:second)
                  expired_ago = current_time - exp

                  Logger.warning("JWT token expired",
                    token_preview: token_preview,
                    expired_seconds_ago: expired_ago,
                    expired_at: DateTime.from_unix!(exp) |> DateTime.to_iso8601(),
                    current_time: DateTime.from_unix!(current_time) |> DateTime.to_iso8601(),
                    subject: claims["sub"],
                    issuer: claims["iss"]
                  )
                rescue
                  _ ->
                    Logger.warning("JWT token expired (unable to decode details)",
                      token_preview: token_preview,
                      reason: reason
                    )
                end
              _ ->
                Logger.warning("JWT token expired (invalid format)",
                  token_preview: token_preview,
                  reason: reason
                )
            end
          _ ->
            Logger.warning("JWT token expired (unable to decode header)",
              token_preview: token_preview,
              reason: reason
            )
        end

      :token_not_yet_valid ->
        Logger.warning("JWT token not yet valid (issued in future)",
          token_preview: token_preview,
          reason: reason
        )

      :invalid_issuer ->
        frontend_api_url =
          Keyword.get(opts, :clerk_frontend_api_url) ||
          ClerkPhoenix.Config.frontend_api_url(otp_app)
        Logger.warning("JWT token has invalid issuer",
          token_preview: token_preview,
          expected_issuer: frontend_api_url,
          reason: reason
        )

      :missing_expiration ->
        Logger.warning("JWT token missing expiration claim",
          token_preview: token_preview,
          reason: reason
        )

      :missing_issued_at ->
        Logger.warning("JWT token missing issued_at claim",
          token_preview: token_preview,
          reason: reason
        )

      :invalid_audience ->
        Logger.warning("JWT token has invalid audience",
          token_preview: token_preview,
          reason: reason
        )

      :missing_required_claims ->
        Logger.warning("JWT token missing required claims (sub)",
          token_preview: token_preview,
          reason: reason
        )

      :token_blacklisted ->
        Logger.warning("JWT token is blacklisted/revoked",
          token_preview: token_preview,
          reason: reason
        )

      :signature_verification_failed ->
        Logger.warning("JWT signature verification failed",
          token_preview: token_preview,
          reason: reason
        )

      _ ->
        Logger.warning("JWT validation failed",
          token_preview: token_preview,
          reason: inspect(reason)
        )
    end
  end
end
