defmodule ClerkPhoenixTest do
  use ExUnit.Case
  doctest ClerkPhoenix

  test "returns version" do
    assert ClerkPhoenix.version() == "0.3.0"
  end
end
