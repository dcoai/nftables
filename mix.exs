defmodule NFTables.MixProject do
  use Mix.Project

  @version "0.8.1"
  @source_url "https://github.com/dcoai/nftables"

  def project do
    [
      app: :nftables,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      compilers: Mix.compilers() ++ [:module_indexer],
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
      {:nftables_port, "~> 0.4.2"},
      {:jason, "~> 1.4"},
      {:usage_rules, "~> 0.1.25", only: :dev},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Elixir library for working with Linux nftables rules. Provides high-level APIs
    for building tables, chains, rules, maps and sets. Works with NFTables.Port for
    communicating with the kernel firewall.
    """
  end

  defp package do
    [
      name: "nftables",
      files: ~w(lib examples .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url
      },
      maintainers: ["Doug ClymerOlson"],
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
        "LICENSE",
        "dev_docs/architecture.md",
        "dev_docs/quick_reference.md"
      ],
      groups_for_modules: [
        "Core API": [
          NFTables,
          NFTables.Expr,
          NFTables.Query
        ],
        "Expression API": [
          NFTables.Expr.Sets,
          NFTables.Expr.NAT,
          NFTables.Expr.Structs,
          NFTables.Expr.CT,
          NFTables.Expr.OSF,
          NFTables.Expr.Meter,
          NFTables.Expr.TCP,
          NFTables.Expr.Payload,
          NFTables.Expr.ARP,
          NFTables.Expr.Socket,
          NFTables.Expr.IP,
          NFTables.Expr.Protocols,
          NFTables.Expr.Actions,
          NFTables.Expr.Metadata,
          NFTables.Expr.Verdict,
          NFTables.Expr.Layer2,
          NFTables.Expr.ICMP,
          NFTables.Expr.UDP,
          NFTables.Expr.IPsec,
          NFTables.Expr.Port          
        ],
        "Convenience API": [
          NFTables.Policy,
          NFTables.NAT
        ],
        Requests: [
          NFTables.Requestor,
          NFTables.Local,
          NFTables.Decoder
        ],
        "Internal API": [
          NFTables.Builder,
          NFTables.Validation,
          NFTables.Expr.Structs,
          NFTables.Formatter
        ]
      ]
    ]
  end
end
