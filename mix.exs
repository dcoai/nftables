defmodule NFTables.MixProject do
  use Mix.Project

  @version "0.5.0"
  @source_url "https://github.com/yourusername/nftables"

  def project do
    [
      app: :nftables,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Test configuration
      test_pattern: "*_test.exs",
      test_coverage: [tool: ExCoveralls],

      # Hex package configuration
      description: description(),
      package: package(),

      # Docs
      name: "NFTables",
      source_url: @source_url,
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:nftables_port, path: "../nftables_port"},
      {:jason, "~> 1.4"},
      {:usage_rules, "~> 0.1.25", only: :dev},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Pure Elixir library for working with Linux nftables rules. Provides high-level APIs
    for building tables, chains, rules, and sets. Works with NFTables.Port for
    communicating with the kernel firewall, or can generate JSON/rule definitions
    independently for inspection, testing, or remote execution.
    """
  end

  defp package do
    [
      name: "nftables",
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Security" => "#{@source_url}/blob/main/SECURITY.md"
      },
      maintainers: ["Your Name"],
      source_url: @source_url
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md",
        "LICENSE"
      ],
      groups_for_modules: [
        "Core API": [
          NFTables.Builder,
          NFTables.Match,
          NFTables.Query
        ],
        "Convenience API": [
          NFTables.Policy,
          NFTables.NAT,
          NFTables.Rule
        ],
        "Execution": [
          NFTables.Local,
          NFTables.Requestor,
          NFTables.Decoder
        ],
        "Internal API": [
          NFTables.Validation,
          NFTables.Expr,
          NFTables.Formatter
        ]
      ]
    ]
  end
end
