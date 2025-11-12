defmodule NFTablesEx.MixProject do
  use Mix.Project

  @version "0.4.0"
  @source_url "https://github.com/yourusername/nftables_ex"

  def project do
    [
      app: :nftables_ex,
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
      name: "NFTablesEx",
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
      {:nftables_ex_port, path: "../nftables_ex_port"},
      {:jason, "~> 1.4"},
      {:usage_rules, "~> 0.1.25", only: :dev},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Pure Elixir library for working with Linux nftables rules. Provides high-level APIs
    for building tables, chains, rules, and sets. Works with NFTablesEx.Port for
    communicating with the kernel firewall, or can generate JSON/rule definitions
    independently for inspection, testing, or remote execution.
    """
  end

  defp package do
    [
      name: "nftables_ex",
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
        "High-Level API": [
          NFTablesEx.Policy,
          NFTablesEx.Match,
          NFTablesEx.Chain,
          NFTablesEx.Table,
          NFTablesEx.Rule,
          NFTablesEx.Set,
          NFTablesEx.Query,
          NFTablesEx.NAT
        ],
        "Execution": [
          NFTablesEx.Executor,
          NFTablesEx.Batch
        ],
        "Internal API": [
          NFTablesEx.Builder,
          NFTablesEx.Validation,
          NFTablesEx.JsonExpr,
          NFTablesEx.Formatter
        ]
      ]
    ]
  end
end
