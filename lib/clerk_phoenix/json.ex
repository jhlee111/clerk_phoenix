defmodule ClerkPhoenix.JSON do
  @moduledoc false

  # Uses the built-in JSON module (Elixir 1.18+) when available,
  # otherwise falls back to Jason.

  if Code.ensure_loaded?(JSON) do
    defdelegate encode!(data), to: JSON
    defdelegate decode(data), to: JSON
    defdelegate decode!(data), to: JSON
  else
    defdelegate encode!(data), to: Jason
    defdelegate decode(data), to: Jason
    defdelegate decode!(data), to: Jason
  end
end
