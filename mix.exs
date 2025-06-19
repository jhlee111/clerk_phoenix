defmodule ClerkPhoenix.MixProject do
  use Mix.Project

  @version "0.1.5"
  @source_url "https://github.com/your-username/clerk_phoenix"

  def project do
    [
      app: :clerk_phoenix,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs(),
      name: "ClerkPhoenix",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {ClerkPhoenix.Application, []}
    ]
  end

  defp deps do
    [
      # Core dependencies
      {:phoenix, "~> 1.7 or ~> 1.8"},
      {:plug, "~> 1.14"},
      {:joken, "~> 2.6"},
      {:jose, "~> 1.11"},
      {:req, "~> 0.4"},
      {:phoenix_live_view, "~> 0.18 or ~> 1.0", optional: true},

      # Development and testing
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false}
    ]
  end

  defp description do
    """
    ClerkPhoenix provides seamless integration between Clerk authentication and Phoenix applications.
    Features include JWT validation, session management, authentication plugs, and security hardening.
    """
  end

  defp package do
    [
      files: ~w(lib priv mix.exs README.md LICENSE CHANGELOG.md),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Clerk" => "https://clerk.com/",
        "Phoenix" => "https://phoenixframework.org/"
      },
      maintainers: ["Your Name"]
    ]
  end

  defp docs do
    [
      main: "ClerkPhoenix",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        "Core": [
          ClerkPhoenix,
          ClerkPhoenix.Auth,
          ClerkPhoenix.Config
        ],
        "Plugs": [
          ClerkPhoenix.Plug.AuthPlug,
          ClerkPhoenix.Plug.FrontendConfigPlug
        ],
        "JWT & Tokens": [
          ClerkPhoenix.JWT,
          ClerkPhoenix.Token,
          ClerkPhoenix.TokenBlacklist
        ],
        "Session": [
          ClerkPhoenix.Session,
          ClerkPhoenix.SessionSecurity
        ],
        "Identity": [
          ClerkPhoenix.Identity,
          ClerkPhoenix.AuthContext
        ],
        "LiveView": [
          ClerkPhoenix.LiveView
        ]
      ]
    ]
  end
end
