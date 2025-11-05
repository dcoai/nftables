defmodule Nftables.MixProject do
  use Mix.Project

  @version "0.4.0"
  @source_url "https://github.com/yourusername/nftex"

  def project do
    [
      app: :nftables,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      compilers: Mix.compilers() ++ [:zig],
      aliases: aliases(),

      # Hex package configuration
      description: description(),
      package: package(),

      # Docs
      name: "NFTex",
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
      {:usage_rules, "~> 0.1.25", only: :dev},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    High-performance Elixir bindings for Linux nftables via libnftnl.
    Provides high-level APIs for firewall management with automatic resource cleanup,
    type safety, and production-ready security features.
    """
  end

  defp package do
    [
      name: "nftex",
      files: ~w(lib priv native/.build.zig native/.build.zig.zon native/src .formatter.exs mix.exs README.md LICENSE CHANGELOG.md SECURITY.md),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
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
        "CHANGELOG.md",
        "SECURITY.md",
        "LICENSE"
      ],
      groups_for_modules: [
        "High-Level API": [
          NFTex.Policy,
          NFTex.RuleBuilder,
          NFTex.Chain,
          NFTex.Table,
          NFTex.Rule,
          NFTex.Set
        ],
        "Low-Level API": [
          NFTex.ExpressionBuilder,
          NFTex.Port,
          NFTex.Query
        ],
        "Kernel Operations": [
          NFTex.Kernel.Table,
          NFTex.Kernel.Chain,
          NFTex.Kernel.Rule,
          NFTex.Kernel.Set,
          NFTex.Kernel.SetElement,
          NFTex.Kernel.Expression,
          NFTex.Kernel.Batch
        ]
      ]
    ]
  end

  defp aliases do
    [
      "compile.zig": &run_zig_compile/1,
      clean: ["clean", &run_zig_clean/1]
    ]
  end

  defp run_zig_compile(_args) do
    Mix.Tasks.Compile.Zig.run([])
  end

  defp run_zig_clean(_args) do
    Mix.Tasks.Compile.Zig.clean()
  end
end
