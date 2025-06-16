defmodule ClerkPhoenix.IdentityTest do
  use ExUnit.Case, async: true

  alias ClerkPhoenix.Identity

  describe "public interface - identity extraction from JWT claims" do
    test "extracts identity from standard JWT claims" do
      claims = %{
        "sub" => "user_123",
        "email" => "test@example.com",
        "given_name" => "John",
        "family_name" => "Doe",
        "picture" => "https://example.com/avatar.jpg"
      }

      {:ok, identity} = Identity.extract_from_claims(claims, :my_app)

      # Applications rely on these fields being extracted
      assert identity["sub"] == "user_123"
      assert identity["email"] == "test@example.com"
      assert identity["name"] == "John Doe"
      assert identity["image_url"] == "https://example.com/avatar.jpg"
    end

    test "handles missing optional fields gracefully" do
      claims = %{
        "sub" => "user_123"
        # Only required field
      }

      {:ok, identity} = Identity.extract_from_claims(claims, :my_app)

      # Should still work with just subject
      assert identity["sub"] == "user_123"
      refute Map.has_key?(identity, "email")
      refute Map.has_key?(identity, "name")
    end

    test "fails when subject identifier is missing" do
      claims = %{
        "email" => "test@example.com"
        # Missing sub/id
      }

      assert {:error, :no_subject_identifier} = Identity.extract_from_claims(claims, :my_app)
    end

    test "validates identity correctly" do
      valid_identity = %{"sub" => "user_123"}
      invalid_identity = %{"email" => "test@example.com"}

      assert :ok = Identity.validate_identity(valid_identity)
      assert {:error, {:missing_fields, ["sub"]}} = Identity.validate_identity(invalid_identity)
    end

    test "estimates identity size for session storage" do
      identity = %{"sub" => "user_123", "email" => "test@example.com"}
      size = Identity.estimate_size(identity)

      # Should return a reasonable byte size
      assert is_integer(size)
      assert size > 0
    end

    test "provides default identity mapping" do
      mapping = Identity.default_identity_mapping()

      # Applications can use this to understand expected structure
      assert mapping[:subject_field] == ["sub", :sub, "id", :id, "user_id", :user_id]
      assert mapping[:email_field] == ["email", :email, "primary_email_address", :primary_email_address]
    end
  end

  describe "flexible claim extraction" do
    test "tries multiple field names for subject" do
      # Test different subject field names that Clerk might use
      test_cases = [
        %{"sub" => "user_123"},
        %{"id" => "user_123"},
        %{"user_id" => "user_123"}
      ]

      for claims <- test_cases do
        {:ok, identity} = Identity.extract_from_claims(claims, :my_app)
        assert identity["sub"] == "user_123"
      end
    end

    test "constructs name from separate first/last fields" do
      claims = %{
        "sub" => "user_123",
        "given_name" => "John",
        "family_name" => "Doe"
      }

      {:ok, identity} = Identity.extract_from_claims(claims, :my_app)
      assert identity["name"] == "John Doe"
    end

    test "prefers full name over constructed name" do
      claims = %{
        "sub" => "user_123",
        "name" => "John Smith",
        "given_name" => "John",
        "family_name" => "Doe"
      }

      {:ok, identity} = Identity.extract_from_claims(claims, :my_app)
      assert identity["name"] == "John Smith"  # Should prefer "name" field
    end
  end
end