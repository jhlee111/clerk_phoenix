defmodule ClerkPhoenix.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Core authentication modules only
      # Future: Add modules like TokenBlacklist when needed
    ]

    opts = [strategy: :one_for_one, name: ClerkPhoenix.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
