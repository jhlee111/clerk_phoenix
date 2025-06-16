defmodule ClerkPhoenix.Identity do
  @moduledoc """
  Identity claim extraction from authenticated tokens.

  This module handles extracting identity information from validated JWT claims
  without making assumptions about user data structure. Applications can configure
  how identity claims are extracted and which fields are considered part of identity.

  Identity claims typically include:
  - Subject identifier (user ID)
  - Email address
  - Name information
  - Organization data
  - Custom claims specific to the application

  This module does NOT handle user management, user models, or user business logic.
  That is the responsibility of the application using ClerkPhoenix.
  """

  require Logger

  @doc """
  Extracts identity claims from validated JWT token claims.

  Takes raw JWT claims and extracts identity-relevant information based on
  configuration. Returns a clean identity map that applications can use
  to fetch or create user records.

  ## Parameters
  - `claims` - Validated JWT claims map
  - `otp_app` - OTP application for configuration lookup

  ## Returns
  - `{:ok, identity}` - Successfully extracted identity claims
  - `{:error, reason}` - Failed to extract required identity information

  ## Examples

      iex> ClerkPhoenix.Identity.extract_from_claims(jwt_claims, :my_app)
      {:ok, %{
        "sub" => "user_2ABC123",
        "email" => "user@example.com",
        "name" => "John Doe",
        "organizations" => [...]
      }}
  """
  def extract_from_claims(claims, otp_app) when is_map(claims) do
    config = ClerkPhoenix.Config.get_config(otp_app)
    identity_mapping = get_in(config, [:identity_mapping]) || default_identity_mapping()

    try do
      identity = %{
        "sub" => extract_field(claims, identity_mapping[:subject_field]),
        "email" => extract_field(claims, identity_mapping[:email_field]),
        "name" => extract_name(claims, identity_mapping),
        "image_url" => extract_field(claims, identity_mapping[:image_field]),
        "organizations" => extract_organizations(claims, identity_mapping)
      }
      |> filter_nil_values()

      # Validate that we have at least a subject identifier
      case identity do
        %{"sub" => sub} when is_binary(sub) and sub != "" ->
          {:ok, identity}
        _ ->
          Logger.warning("Identity extraction failed: no valid subject identifier found",
            claims_preview: inspect(Map.take(claims, ["sub", "id", "user_id"]))
          )
          {:error, :no_subject_identifier}
      end
    rescue
      error ->
        Logger.error("Identity extraction error: #{inspect(error)}",
          claims_preview: inspect(Map.take(claims, ["sub", "id", "email"]))
        )
        {:error, :extraction_failed}
    end
  end

  @doc """
  Gets the default identity mapping configuration.

  This provides fallback field mappings when no specific configuration is provided.
  Applications can override this through configuration.

  ## Returns
  Map with field mapping configurations for common identity claims.
  """
  def default_identity_mapping do
    %{
      subject_field: ["sub", :sub, "id", :id, "user_id", :user_id],
      email_field: ["email", :email, "primary_email_address", :primary_email_address],
      first_name_field: ["given_name", :given_name, "first_name", :first_name],
      last_name_field: ["family_name", :family_name, "last_name", :last_name],
      name_field: ["name", :name, "full_name", :full_name],
      image_field: ["picture", :picture, "image_url", :image_url, "avatar", :avatar],
      organizations_field: ["org", :org, "organizations", :organizations, "orgs", :orgs]
    }
  end

  @doc """
  Validates that an identity map contains required fields.

  ## Parameters
  - `identity` - Identity map to validate
  - `required_fields` - List of required field names (defaults to ["sub"])

  ## Returns
  - `:ok` - Identity is valid
  - `{:error, reason}` - Identity is missing required fields

  ## Examples

      iex> ClerkPhoenix.Identity.validate_identity(%{"sub" => "user_123"})
      :ok

      iex> ClerkPhoenix.Identity.validate_identity(%{"email" => "test@example.com"})
      {:error, :missing_subject}
  """
  def validate_identity(identity, required_fields \\ ["sub"]) do
    missing_fields = Enum.filter(required_fields, fn field ->
      case Map.get(identity, field) do
        nil -> true
        "" -> true
        _ -> false
      end
    end)

    if missing_fields == [] do
      :ok
    else
      {:error, {:missing_fields, missing_fields}}
    end
  end

  @doc """
  Estimates the size of identity data for session storage.

  This helps applications determine if identity data will fit in session cookies
  or if alternative storage mechanisms are needed.

  ## Parameters
  - `identity` - Identity map to measure

  ## Returns
  Integer representing estimated byte size of the identity data.
  """
  def estimate_size(identity) when is_map(identity) do
    identity
    |> Jason.encode!()
    |> byte_size()
  end

  # Private functions

  defp extract_field(claims, field_candidates) when is_list(field_candidates) do
    Enum.find_value(field_candidates, fn field ->
      case field do
        field when is_binary(field) -> claims[field]
        field when is_atom(field) -> claims[field]
        _ -> nil
      end
    end)
  end

  defp extract_field(claims, field) when is_binary(field) or is_atom(field) do
    claims[field]
  end

  defp extract_field(_claims, _), do: nil

  defp extract_name(claims, identity_mapping) do
    # Try to get full name first, then construct from first/last
    case extract_field(claims, identity_mapping[:name_field]) do
      name when is_binary(name) and name != "" ->
        name
      _ ->
        first = extract_field(claims, identity_mapping[:first_name_field])
        last = extract_field(claims, identity_mapping[:last_name_field])
        construct_full_name(first, last)
    end
  end

  defp construct_full_name(first, last) when is_binary(first) and is_binary(last) do
    "#{first} #{last}" |> String.trim()
  end

  defp construct_full_name(first, _) when is_binary(first), do: first
  defp construct_full_name(_, last) when is_binary(last), do: last
  defp construct_full_name(_, _), do: nil

  defp extract_organizations(claims, identity_mapping) do
    case extract_field(claims, identity_mapping[:organizations_field]) do
      orgs when is_list(orgs) -> orgs
      org when is_map(org) -> [org]
      _ -> []
    end
  end

  defp filter_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end