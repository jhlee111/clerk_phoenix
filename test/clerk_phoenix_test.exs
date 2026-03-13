defmodule ClerkPhoenixTest do
  use ExUnit.Case
  doctest ClerkPhoenix

  test "returns version" do
    assert ClerkPhoenix.version() == "0.2.0"
  end
end
